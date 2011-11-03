package t::AuthZ;
use parent "Plack::Middleware::AuthZ::Base";
sub match { $_[0]->{_match}->($_[1]) }
1;
