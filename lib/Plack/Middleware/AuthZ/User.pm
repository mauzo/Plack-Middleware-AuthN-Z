package Plack::Middleware::AuthZ::User;

use warnings;
use strict;

our $VERSION = "1";

use parent "Plack::Middleware::AuthZ::Base";

sub match { defined $_[1]{REMOTE_USER} }

1;
