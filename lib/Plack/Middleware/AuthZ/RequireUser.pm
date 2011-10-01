package Plack::Middleware::AuthZ::RequireUser;
use warnings;
use strict;
use parent "Plack::Middleware";

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
