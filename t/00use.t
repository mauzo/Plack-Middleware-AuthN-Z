#!/usr/bin/perl

use warnings;
use strict;

use Test::More;

my @AuthN = qw( Basic );
my @AuthZ = qw( All User );
my @Util  = qw( Static ); 

for (map "Plack::Middleware::$_",
    qw( AuthN AuthZ AuthZ::Base ),
    (map "AuthN::$_", @AuthN),
    (map "AuthZ::$_", @AuthZ),
    (map "Util::$_", @Util),
) {
    use_ok $_;
    isa_ok $_, "Plack::Middleware", $_;
}

isa_ok $_, "Plack::Middleware::AuthN", $_ 
    for map "Plack::Middleware::AuthN::$_", @AuthN;

isa_ok $_, "Plack::Middleware::AuthZ::Base", $_ 
    for map "Plack::Middleware::AuthZ::$_", @AuthZ;

BAIL_OUT "modules don't load correctly!"
    if grep !$_, Test::More->builder->summary;

done_testing;
