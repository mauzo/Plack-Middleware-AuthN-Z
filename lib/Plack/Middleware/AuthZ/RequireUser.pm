package Plack::Middleware::AuthZ::RequireUser;

use warnings;
use strict;

our $VERSION = "1";

use parent "Plack::Middleware";

=head1 NAME

Plack::Middleware::AuthZ::RequireUser - Require REMOTE_USER is set

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
    my ($self, $env) = @_;
    defined $env->{REMOTE_USER} or return $self->unauthorized;
    $self->app->($env);
}

sub unauthorized {
    my ($self) = @_;
    my $body = 'Authorization required';
    my $res = [
        401,
        [ 'Content-Type' => 'text/plain',
          'Content-Length' => length $body,
        ],
        [ $body ],
    ];
    return $res;
}

1;

=head1 AUTHOR

Copyright 2011 Ben Morrow <ben@morrow.me.uk>.

=head1 SEE ALSO

L<Plack>, L<Plack::AuthN>

=cut
