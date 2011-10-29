package Plack::Middleware::Util::Static;

use warnings;
use strict;

our $VERSION = "1";

use parent "Plack::Middleware";

use Scalar::Util;
use Plack::Util::Accessor   qw/static/;

my %Canned = (
    401 => [401,
        [Content_Type => "text/plain"], 
        ["Authorization required"],
    ],
);

sub new {
    my ($class, @args) = @_;
    my $args;

    if (@args == 1) {
        my $type = Scalar::Util::reftype $args[0];
        if (not defined $type) {
            $args = { static => $Canned{$args[0]} };
        }
        elsif ($type eq "HASH") {
            $args = $args[0];
        }
        elsif ($type eq "ARRAY") {
            $args = { static => $args[0] };
        }
        else {
            Carp::croak "Unexpected $type reference";
        }
    }
    else {
        $args = { @args };
    }

    return $class->SUPER::new($args);
}

sub call { $_[0]->static }

1;

