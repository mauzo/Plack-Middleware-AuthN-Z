package Plack::Middleware::AuthN;

use warnings;
use strict;

our $VERSION = "1";

use parent qw(Plack::Middleware);

use Plack::Util;
use Scalar::Util;
use MIME::Base64;

=head1 NAME

Plack::Middleware::AuthN - Stackable Plack authentication

=head1 SYNOPSIS

    use Plack::Builder;

    my $app     = sub { ... };
    my $do_auth = sub {
        my ($user, $passwd) = @_;
        ...
    };

    builder {
        enable "AuthN::Basic", authenticator => $do_auth;
        enable "AuthZ::RequireUser";
        $app;
    };

=head1 DESCRIPTION

<Not yet>

=cut

sub call {
    my($self, $env) = @_;

    my $ok  = $self->_do_auth($env);
    my $nok = $self->challenge($env);

    my $res = $self->app->($env);

    Plack::Util::response_cb($res, sub {
	my ($res) = @_;
        my $cb = ($res->[0] == 401) ? $nok : $ok;
        $cb and $cb->($res);
	return;
    });
}

sub _do_auth {
    my ($self, $env) = @_;

    my $user = delete $env->{REMOTE_USER};
    my $cleanup;

    # defer to auth schemes higher in the chain
    if (not defined $user) {
        ($user, $cleanup) = $self->do_auth($env);
    }

    $env->{REMOTE_USER} = $user;
    return $cleanup;
}

sub do_auth {
    my ($self, $env) = @_;

    my $auth = $env->{HTTP_AUTHORIZATION};
    my $type = $self->http_auth_type;

    my $user;
    if ($auth and $auth =~ /^$type (?: [ \t]+ (.*) )?/ix) {
        $user = $self->do_http_auth($env, $1);
    }

    return $user;
}

=item C<< $self->_b64($base64) >>

Most HTTP authentication schemes use the Base64 encoding. While
MIME::Base64 can be used to decode base64 data, it is more liberal than
is really desirable for an authentication module. Subclasses can call
C<< ->_b64 >> to safely verify and decode base64 data. This method
allows but does not require trailing C<=> padding, and ignores leading
and trailing whitespace, but otherwise requires strict base64 data.

=cut

sub _b64 {
    my ($self, $text) = @_;
    my ($b64) = $text =~ m[
        ^ [ \t]*
        ([A-Za-z0-9+/]+) ={0,2}
        [ \t]* \z
    ]x or return;
    MIME::Base64::decode_base64 $b64;
}

sub challenge {
    my ($self, $env) = @_;
    sub {
        my ($res) = @_;
        my $type    = $self->http_auth_type;  
        my $chal    = $self->http_auth_challenge($env);

        Plack::Util::header_push $res->[1],
            "WWW-Authenticate" => "$type $chal";
    };
}

1;

=head1 AUTHOR

Copyright 2011 Ben Morrow <ben@morrow.me.uk>.

Based on Plack::Middleware::Auth::Basic by Tatsuhiko Miyagawa.

=head1 SEE ALSO

L<Plack>, L<Plack::Middleware::AuthZ>, L<Plack::Middleware::Auth::Basic>.

=cut
