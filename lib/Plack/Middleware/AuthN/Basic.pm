package Plack::Middleware::AuthN::Basic;
use strict;
use parent qw(Plack::Middleware::AuthN);
use Plack::Util::Accessor qw( realm authenticator );
use Scalar::Util;
use MIME::Base64;

sub prepare_app {
    my $self = shift;

    my $auth = $self->authenticator or die 'authenticator is not set';
    if (Scalar::Util::blessed($auth) && $auth->can('authenticate')) {
        $self->authenticator(sub { $auth->authenticate(@_[0,1]) }); # because Authen::Simple barfs on 3 params
    } elsif (ref $auth ne 'CODE') {
        die 'authenticator should be a code reference or an object that responds to authenticate()';
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

__END__

=head1 NAME

Plack::Middleware::Auth::Basic - Simple basic authentication middleware

=head1 SYNOPSIS

  use Plack::Builder;
  my $app = sub { ... };

  builder {
      enable "Auth::Basic", authenticator => \&authen_cb;
      $app;
  };

  sub authen_cb {
      my($username, $password) = @_;
      return $username eq 'admin' && $password eq 's3cr3t';
  }

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

Tatsuhiko Miyagawa

=head1 SEE ALSO

L<Plack>

=cut
