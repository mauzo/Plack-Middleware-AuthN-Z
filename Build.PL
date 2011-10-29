use Module::Build;

Module::Build->new(
    dist_name           => "Plack-Middleware-AuthN+Z",
    dist_version_from   => "lib/Plack/Middleware/AuthN.pm",
    license             => "bsd",
    configure_requires  => {
        "Module::Build"     => "0.38",
    },
    build_requires      => {
        "Test::More"        => "0.65",
    },
    requires            => {
        "Plack"             => 0,

        # AuthN::Basic
        "Scalar::Util"      => 0,
        "MIME::Base64"      => 0,
    },
)->create_build_script;
