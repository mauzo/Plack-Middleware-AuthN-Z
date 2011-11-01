package t::AuthN::Http;

use parent "Plack::Middleware::AuthN";

sub http_auth_type      { $_[0]{http_type} }
sub do_http_auth        { $_[0]{http_auth}(@_[1,2]) }
sub http_auth_challenge { $_[0]{http_chal}($_[1])   }

1;
