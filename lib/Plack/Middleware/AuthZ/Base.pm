package Plack::Middleware::AuthZ::Base;

use warnings;
use strict;

our $VERSION = "1";

use parent "Plack::Middleware";
use Plack::Util::Accessor       qw/on_match/;

sub call {
    my ($self, $env) = @_;
    if ($self->match($env)) {
        $self->on_match->($env);
    }
    else {
        $self->app->($env);
    }
}

1;
