package t::Util;

use warnings;
use strict;

use Test::More;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;

use Carp;
#$SIG{__DIE__}   = sub { Carp::confess($_[0]) };
#$SIG{__WARN__}  = sub { Carp::cluck($_[0]) };

use Exporter;
our @EXPORT = (
    @Test::More::EXPORT,
    @Plack::Test::EXPORT,
    @Plack::Builder::EXPORT,
    @HTTP::Request::Common::EXPORT,
    qw( %t APP wrap_SET authn_cb check_authn ),
);

sub import {
    warnings->import;
    strict->import;
    goto &Exporter::import;
}

our %t;

sub APP {
    my (undef, $status, @vars) = split m!/!, $_[0]{PATH_INFO};
    local $" = ":";
    note "APP: [$status], [@vars]";
    return [$status,
        ["Content-type" => "text/plain"],
        [join "\0", @{$_[0]}{@vars}],
    ];
}

sub wrap_SET {
    my ($app) = @_;
    sub {
        my ($env) = @_;
        my $set = $t{SET};
        note "SET: [$_] => [$$set{$_}]" for keys %$set;
        $env->{$_} = $set->{$_} for keys %$set;
        $app->($env);
    }
}

{
    my $cb;
    my @calls = qw/auth challenge cleanup/;

    sub authn_cb { ($cb) = @_ }

    sub check_authn {
        my ($path, $hdrs, $code, $call, $content, $name) = @_;

        my $res     = $cb->(GET "http://localhost/$path", @$hdrs);
        my %call    = map +($_, 1), split / /, $call;

        is $res->code,  $code,      "$name has correct status code";
        for (@calls) {
            if ($call{$_}) {
                is $t{$_}, 1,       "$name does call $_";
            }
            else {
                is $t{$_}, undef,   "$name doesn't call $_";
            }
        }
        is $res->content, $content, "$name has correct content";
    }
}

1;
