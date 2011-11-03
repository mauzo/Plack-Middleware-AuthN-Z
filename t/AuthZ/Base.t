use t::Util;

my $app = builder {
    enable \&SET;
    enable "+t::AuthZ", (
        _match       => sub { 
            $t{match}++;
            $t{match_env} = $_[0]->{TO_MATCH}; 
            $_[0]->{FROM_MATCH} = $t{from_match};
            $t{result};
        },
        on_match    => sub {
            $t{on_match}++;
            $t{after}->($_[0]);
        },
    );
    \&APP;
};

test_psgi app => $app, client => sub {
    auth_cb $_[0];
    auth_calls (
        match       => 1,       "call match",
        match_env   => "blib",  "see the psgi env",
        on_match    => 1,       "call on_match",
    );

    my @blib = (
        from_match  => "blob",
        SET         => {TO_MATCH => "blib"},
        after       => \&APP,
    );

    my $try = "match match_env";
    for (
        [1,     "$try on_match",    "match"     ],
        [0,     $try,               "no match"  ],
    ) {
        my ($result, $calls, $rname) = @$_;

    for my $status (200, 401, 302) {

        my $name = join ", ", $status, $rname;

        %t = (@blib, result => $result);
        check_auth "$status/FROM_MATCH", [],
            $status, $calls, [], "blob",
            $name;
    } }
};

done_testing;
