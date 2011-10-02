package Plack::Middleware::AuthN::Basic;

use warnings;
use strict;

use parent qw(Plack::Middleware::AuthN);

our $VERSION = "1";

use Plack::Util::Accessor qw( realm authenticator );
use Scalar::Util;
use MIME::Base64;

=head1 NAME

Plack::Middleware::AuthN::Basic - Stackable Basic authentication

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

Plack::Middleware::Auth::Basic is a basic authentication handler for Plack.

=head1 CONFIGURATION

=over 4

=item authenticator

A callback function that takes username and password supplied and
returns whether the authentication succeeds. Required.

Authenticator can also be an object that responds to C<authenticate>
method that takes username and password and returns boolean, so
backends for L<Authen::Simple> is perfect to use:

  use Authen::Simple::LDAP;
  enable "Auth::Basic", authenticator => Authen::Simple::LDAP->new(...);

=item realm

Realm name to display in the basic authentication dialog. Defaults to I<restricted area>.

=back

=cut

sub prepare_app {
    my ($self) = @_;
    my $auth = $self->authenticator or die 'authenticator is not set';

    if (Scalar::Util::blessed($auth) && $auth->can('authenticate')) {
        # because Authen::Simple barfs on 3 params
        $self->authenticator(sub { $auth->authenticate(@_[0,1]) });
    } elsif (ref $auth ne 'CODE') {
        die "authenticator should be a code reference " .
            "or an object that responds to authenticate()";
    }

    $self->SUPER::prepare_app;
}

sub http_auth_type { "Basic" }

sub do_http_auth {
    my ($self, $env, $b64) = @_;

    my($user, $pass) = split /:/, (MIME::Base64::decode($b64) || ":");
    $pass = '' unless defined $pass;
    if ($self->authenticator->($user, $pass, $env)) {
        return $user;
    }

    return;
}

sub http_auth_challenge {
    my $self = shift;
    return 'realm="' . ($self->realm || "restricted area") . '"';
}

1;

=head1 LIMITATIONS

This middleware expects that the application has a full access to the
headers sent by clients in PSGI environment. That is normally the case
with standalone Perl PSGI web servers such as L<Starman> or
L<HTTP::Server::Simple::PSGI>.

However, in a web server configuration where you can't achieve this
(i.e. using your application via Apache's mod_cgi), this middleware
does not work since your application can't know the value of
C<Authorization:> header.

If you use Apache as a web server and CGI to run your PSGI
application, you can either a) compile Apache with
C<-DSECURITY_HOLE_PASS_AUTHORIZATION> option, or b) use mod_rewrite to
pass the Authorization header to the application with the rewrite rule
like following.

  RewriteEngine on
  RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization},L]

=head1 AUTHOR

Copyright 2011 Ben Morrow <ben@morrow.me.uk>.

Based on Plack::Middleware::Auth::Basic by Tatsuhiko Miyagawa.

=head1 SEE ALSO

L<Plack>, L<Plack::Middleware::AuthN>, L<Plack::Middleware::AuthZ>,
L<Plack::Middleware::Auth::Basic>.

=cut
