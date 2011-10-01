package Plack::Middleware::AuthN;
use strict;
use parent qw(Plack::Middleware);
use Plack::Util::Accessor qw( passthrough );
use Plack::Util;
use Scalar::Util;

# Intended usage is like:
#
#   builder {
#       enable "Auth::Negotiate",
#           <whatever>,
#           passthrough => 1;
#
#       enable "Auth::Basic", 
#           authenticator => ...,
#           passthrough => 1;
#
#       $app;
#   }
#
#   If there is no auth provided, the request gets passed through to
#   $app without REMOTE_USER set. It's up to $app (or some lower
#   middleware) to reject it with a 401 if it needs to, which will make
#   both Basic and Negotiate add their own WWW-Auth headers as the
#   response passes back up the chain.
#
#   The intent is that this base class should be usable for non-RFC2617
#   auth schemes (forms, OAuth, ...) as well. Such schemes would
#   override do_auth and challenge rather than the _http_ equivalents,
#   and could use the $cleanup callback from do_auth to add cookies to
#   the response (or whatever).
#
#   The 'passthrough' parameter is just for compatibility, so Basic
#   continues to work the same as at present without it. Without it
#   Basic will insert ACL::RequireUser below itself in the chain, which
#   returns 401 if REMOTE_USER isn't set.

sub prepare_app {
    my ($self) = @_;

    unless ($self->passthrough) {
        # emulate the old behaviour
        require Plack::Middleware::AuthZ::RequireUser;
        $self->app(Plack::Middleware::AuthZ::RequireUser->wrap($self->app));
    }
}

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
