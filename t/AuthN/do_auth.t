#!/usr/bin/perl

use t::Util;

{   package t::AuthN;
    use parent "Plack::Middleware::AuthN";

    sub do_auth { $_[0]{user}($_[1]), $_[0]{cleanup} }
    sub challenge { $_[0]{challenge} }
}

my $app = wrap_SET +t::AuthN->new(
    user        => sub { $t{auth}++; $t{user} },
    cleanup     => sub { $t{cleanup}++ },
    challenge   => sub { $t{challenge}++ },
)->wrap(\&APP);

test_psgi app => $app, client => sub {
    authn_cb $_[0];

    my @bob  = (user => "bob");
    my @bill = (user => "bob", SET => {REMOTE_USER => "bill"});

    %t = @bob;
    check_authn "200/REMOTE_USER", [], 
        200, "auth cleanup", "bob",
        "200";

    %t = @bob;
    check_authn "401/REMOTE_USER", [],
        401, "auth challenge", "bob",
        "401";

    %t = @bob;
    check_authn "302/REMOTE_USER", [],
        302, "auth cleanup", "bob",
        "302";

    %t = @bill;
    check_authn "200/REMOTE_USER", [],
        200, "", "bill",
        "200 with REMOTE_USER";

    %t = @bill;
    check_authn "401/REMOTE_USER", [],
        401, "challenge", "bill",
        "401 with REMOTE_USER";
};

done_testing;
