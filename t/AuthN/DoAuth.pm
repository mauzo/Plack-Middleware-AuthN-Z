package t::AuthN::DoAuth;
use parent "Plack::Middleware::AuthN";

sub do_auth { $_[0]{user}($_[1]), $_[0]{cleanup} }
sub challenge { $_[0]{challenge} }

1;
