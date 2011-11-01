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
    qw( %t APP SET authn_cb authn_calls cbGET check_authn ),
);

sub import {
    warnings->import;
    strict->import;
    goto &Exporter::import;
}

our %t;

sub APP {
    my (undef, $status, $var, $hdr) = split m!/!, $_[0]{PATH_INFO};
    note "APP: " . join ", ", map "[$_]", grep defined, $status, $var, $hdr;
    my @hdr = $hdr ? (split /=/, $hdr) : ();
    return [$status,
        ["Content-type" => "text/plain", @hdr],
        [$_[0]{$var}],
    ];
}

sub SET {
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

    sub authn_cb { ($cb) = @_ }

    sub cbGET {
        my ($path, @hdrs) = @_;
        $cb->(GET "http://localhost/$path", @hdrs);
    }
}

{
    my %calls;
    sub authn_calls { %calls = @_ }

    sub check_authn {
        my ($path, $hdrs, $code, $call, $rsph, $content, $name) = @_;

        my $res     = cbGET $path, @$hdrs;
        my %call    = map +($_, 1), split / /, $call;

        is $res->code,  $code,          "$name has correct status code";
        for (keys %calls) {
            if ($call{$_}) {
                is $t{$_}, $calls{$_},  "$name does $_";
            }
            else {
                is $t{$_}, undef,       "$name doesn't $_";
            }
        }
        my @rsph = @$rsph;  # copy, since we trash the original
        while (@rsph) {
            my ($h, $want) = (shift @rsph, shift @rsph);
            my @got = $res->header($h);
            my $got = "GOT: " . ( 
                @got ? (join "", map "\n  $_", @got)
                    : "(no $h headers)"
            );
            if (defined $want) {
                ok grep($_ eq $want, @got), 
                                        "$name has $h: $want"
                    or diag $got;
            }
            else {
                ok !@got,               "$name has no $h headers"
                    or diag $got;
            }
        }
        is $res->content, $content,     "$name has correct content";
    }
}

1;
