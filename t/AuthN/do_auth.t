#!/usr/bin/perl

use t::Util;

{
    my $app = builder {
        enable \&SET;
        enable "+t::AuthN::DoAuth", (
            user        => sub { $t{auth}++; $t{user} },
            cleanup     => sub { $t{cleanup}++ },
            challenge   => sub { $t{challenge}++ },
        );
        \&APP;
    };
    auth_calls auth => 1, cleanup => 1, challenge => 1;

    test_psgi app => $app, client => sub {
        auth_cb $_[0];

        my @bob  = (user => "bob");
        my @bill = (user => "bob", SET => {REMOTE_USER => "bill"});

        %t = @bob;
        check_auth "200/REMOTE_USER", [], 
            200, "auth cleanup", [], "bob",
            "200";

        %t = @bob;
        check_auth "401/REMOTE_USER", [],
            401, "auth challenge", [], "bob",
            "401";

        %t = @bob;
        check_auth "302/REMOTE_USER", [],
            302, "auth cleanup", [], "bob",
            "302";

        %t = @bill;
        check_auth "200/REMOTE_USER", [],
            200, "", [], "bill",
            "200 with REMOTE_USER";

        %t = @bill;
        check_auth "401/REMOTE_USER", [],
            401, "challenge", [], "bill",
            "401 with REMOTE_USER";
    };
}

{
    my $hget = sub { Plack::Util::header_get $_[0][1], $_[1] };
    my $hset = sub { Plack::Util::header_set $_[0][1], @_[1,2] };
    my $app = builder {
        enable \&SET;
        enable "+t::AuthN::DoAuth", (
            user        => sub { 
                my ($env) = @_;
                $t{toauth}          = $$env{TO_AUTH};
                $$env{FROM_AUTH}    = $t{fromauth};
                $t{user};
            },
            cleanup     => sub {
                my ($res) = @_;
                $t{toclean} = $hget->($res, "To-Cleanup");
                $hset->($res, "From-Cleanup", $t{fromclean});
            },
            challenge   => sub {
                my ($res) = @_;
                $t{tochal} = $hget->($res, "To-Challenge");
                $hset->($res, "From-Challenge", $t{fromchal});
            },
        );
        \&APP;
    };

    my %phases = (
        auth => sub {
            my ($r, $n) = @_;
            is $t{toauth}, "toauth",    "$n: do_auth receives env";
            is $r->content, "fromauth", "$n: do_auth affects env";
        },
        cleanup => sub {
            my ($r, $n) = @_;
            is $t{toclean}, "toclean",  "$n: cleanup receives response";
            is $r->header("From-Cleanup"), "fromclean",
                                        "$n: cleanup affects response";
        },
        challenge => sub {
            my ($r, $n) = @_;
            is $t{tochal}, "tochal",    "$n: challenge receives response";
            is $r->header("From-Challenge"), "fromchal",
                                        "$n: challenge affects response";
        },
    );

    test_psgi app => $app, client => sub {
        auth_cb $_[0];
        my @tofrom = (
            (map +($_, $_), qw/fromauth fromclean fromchal/),
            SET => { TO_AUTH => "toauth" },
        );

        %t = @tofrom;
        my $res = auth_GET "200/FROM_AUTH/To-Cleanup=toclean";

        $phases{auth}       ->($res, "200");
        $phases{cleanup}    ->($res, "200");

        %t = @tofrom;
        $res = auth_GET "401/FROM_AUTH/To-Challenge=tochal";

        $phases{auth}       ->($res, "401");
        $phases{challenge}  ->($res, "401");

        %t = @tofrom;
        $res = auth_GET "302/FROM_AUTH/To-Cleanup=toclean";

        $phases{auth}       ->($res, "302");
        $phases{cleanup}    ->($res, "302");

        %t = @tofrom;
        $t{SET}{REMOTE_USER} = "bill";
        $res = auth_GET "401/x/To-Challenge=tochal";

        $phases{challenge}  ->($res, "401 with REMOTE_USER");
    };
}

done_testing;
