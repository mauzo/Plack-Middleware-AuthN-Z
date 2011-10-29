use t::Util;

my $app = sub { 
    return [ 200, [ 'Content-Type' => 'text/plain' ], 
        [ "Hello $_[0]->{REMOTE_USER}" ] ] 
};
$app = builder {
    enable "AuthN::Basic", authenticator => \&cb;
    enable "AuthZ", acl => [ 
        "allow User",
        "deny",
    ];
    $app;
};

sub cb {
    my($username, $password) = @_;
    return $username eq 'admin' && $password eq 's3cr3t';
}

test_psgi app => $app, client => sub {
    my $cb = shift;

    my $res = $cb->(GET "http://localhost/");
    is $res->code, 401;

    my $req = GET "http://localhost/", "Authorization" => "Basic YWRtaW46czNjcjN0";
    $res = $cb->($req);
    is $res->code, 200;
    is $res->content, "Hello admin";
};
done_testing;

