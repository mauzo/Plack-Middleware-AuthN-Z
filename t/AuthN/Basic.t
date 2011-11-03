use t::Util;

my $cb = sub {
    @t{"user", "passwd"} = @_;
    $t{cb}++;
    $t{result};
};

{   package t::AuthN::Basic::Auth;
    use t::Util;
    sub new { bless [] }
    sub authenticate {
        (undef, @t{"user", "passwd"}) = @_;
        $t{cb}++;
        $t{result};
    }
}

for (
    [$cb,                           "coderef"   ],
    [t::AuthN::Basic::Auth->new,    "object"    ],
) {
    my ($actr, $acname) = @$_;

for (
    ["My Realm",        "explicit realm"],
    [undef,             "default realm" ],
) {
    my ($realm, $rlname) = @$_;

    my $app = builder {
        enable \&SET;
        enable "AuthN::Basic", (
            authenticator => $actr,
            ($realm ? (realm => $realm) : ())
        );
        \&APP;
    };

    $realm ||= "restricted area";

    test_psgi app => $app, client => sub {
        auth_cb $_[0];
        auth_calls (
            cb      => 1,
            user    => "bob",
            passwd  => "blob",
        );

my $b64 = "Ym9iOmJsb2I";
for (
    ["",                    0,  "no Auth header"        ],
    ["Basic $b64",          1,  "valid Auth header"     ],
    ["XMauzo 1234",         0,  "invalid Auth header"   ],
    ["Basic *%&^",          0,  "bad base64"            ],
    ["Basic *&$b64",        0,  "bad-then-good b64"     ],
    ["Basic $b64*&",        0,  "good-then-bad b64"     ],
    ["Basic $b64=",         1,  "b64 with trailing ="   ],
    ["Basic Y*m9iOmJsb2I",  0,  "b64 with bad chars"    ],
    ["Basic Ym9i",          0,  "b64 with no :"         ],
) {
    my ($auth, $aok, $aname) = @$_;

for (
    [undef,         0,  "cb returns undef"          ],
    ["",            0,  "cb returns empty string"   ],
    [0,             0,  "cb returns zero"           ],
    [1,             1,  "cb returns 1"              ],
    ["bill",        1,  "cb returns bill"           ],
) {
    my ($result, $rsok, $rsname) = @$_;

for (
    [200,   []                                              ],
    [401,   ["WWW-Authenticate", qq/Basic realm="$realm"/]  ],
    [302,   [],                                             ],
) {
    my ($status, $rsph) = @$_;

    my @auth = $auth            ? (Authorization => $auth)  : ();
    my $user = $aok && $rsok    ? "bob"                     : "";
    my $call = $aok             ? "cb user passwd"          : "";

    my $name = join ", ", $status, $aname, $rlname, $acname, $rsname;

    %t = (result => $result);
    check_auth "$status/REMOTE_USER", \@auth,
        $status, $call, $rsph, $user,
        $name;

} } } }; } }

done_testing;

