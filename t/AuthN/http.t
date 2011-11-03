#!/usr/bin/perl

use t::Util;
use URI::Escape qw/uri_escape/;

{
    my $app = builder {
        enable \&SET;
        enable "+t::AuthN::Http", (
            http_type   => "XMauzo",
            http_auth   => sub { 
                my ($env, $auth) = @_;
                $t{auth}++; 
                $t{authheader}  = $auth; 
                $t{authenv}     = $env->{TO_HTTP_AUTH};
                $t{user};
            },
            http_chal   => sub { $t{challenge}++; $t{wwwauth} },
        );
        \&APP;
    };

    test_psgi app => $app, client => sub {
        auth_cb $_[0];
        auth_calls (
            auth        => 1,
            challenge   => 1,
            authheader  => "blib",
            authenv     => "blub",
        );

        my @bob  = (user => "bob", wwwauth => "blob");

        for (
            [undef,         ""          ],
            ["Basic 67890", "+Basic"    ],
        ) {
            my ($xwww, $wname) = @$_;

        for (
            ["",            0,  "no auth"],
            ["XMauzo blib", 1,  "valid auth"],
            ["Basic 12345", 0,  "invalid auth"],
        ) {
            my ($auth, $doauth, $aname) = @$_;

        for (
            [[],                        0,  ""              ],
            [[REMOTE_USER => "bill"],   1,  "REMOTE_USER"   ],
        ) {
            my ($set, $doset, $sname) = @$_;

        for (
            [200,   0,  undef           ],
            [401,   1,  "XMauzo blob"   ],
            [302,   0,  undef           ],
        ) {
            my ($status, $scall, $mywww) = @$_;

            my $name = join ", ", grep length,
                $status, $sname, $aname, $wname;

            my $call = join " ", (
                ($scall             ? "challenge"               : ""),
                ($doauth && !$doset ? "auth authheader authenv" : ""),
            );
            my $user = $doset ? "bill" : $doauth ? "bob" : "";

            my $rsph = $xwww 
                ? "/WWW-Authenticate=" . uri_escape $xwww
                : "";
            my @auth = $auth ? ("Authorization" => $auth) : ();
            my @wwwa = grep length, $mywww, $xwww;
            @wwwa or @wwwa = undef;
            @wwwa = map +("WWW-Authenticate", $_), @wwwa;

            %t = (@bob, SET => {@$set, TO_HTTP_AUTH => "blub"});
            check_auth 
                "$status/REMOTE_USER$rsph", \@auth,
                $status, $call, \@wwwa, $user,
                $name;
        } } } }
    };
}

done_testing;
