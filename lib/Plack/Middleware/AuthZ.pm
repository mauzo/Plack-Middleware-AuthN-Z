package Plack::Middleware::AuthZ;

use warnings;
use strict;

our $VERSION = "1";

use parent "Plack::Middleware";

use Carp;
use Scalar::Util                qw/blessed reftype/;
use Plack::Util;

use namespace::clean;

use Plack::Util::Accessor       qw/acl on_allow on_deny on_call/;

=head1 NAME

Plack::Middleware::AuthZ - Stackable authorization

=head1 SYNOPSIS

    use Plack::Builder;
    use Plack::Middleware::AuthZ::Builder;

    builder {
        # Individual MWs
        enable "AuthZ::User";

        # Ordered list
        enable "AuthZ", acl => [
            "allow IP 10.0.0.0/24",
            [qw/allow User/],
            "deny",
        ];

        # DSL
        authz {
            on_deny "Util::Static", [
                401,
                [Content_Type => "text/plain"],
                ["Authorization required"],
            ];
            allow "User";
            deny;
        };
    }

=cut

sub call { $_[0]->on_call->($_[1]) }

sub _resolve_mw {
    my ($mw) = @_;

    ref $mw or $mw = [split / /, $mw];

    if (blessed $mw) {
        eval { $mw->isa("Plack::Middleware") }
            or croak "Not a Plack middleware: $mw";
        return sub { $mw->wrap($_[0]) };
    }
    
    my $rt = reftype $mw;
    if ($rt eq "CODE") {
        return $mw;
    }
    if ($rt eq "ARRAY") {
        my ($class, @args) = @$mw;
        $class = Plack::Util::load_class $class, "Plack::Middleware";
        # ->new->wrap so ->new doesn't have to take a hashref
        return sub { $class->new(@args)->wrap($_[0]) };
    }
    croak "Unexpected $rt ref";
}

sub _prepare_stack {
    my ($self, $on) = @_;
    my $stack = $self->$on;

    ref $stack              or $stack = [$stack];
    ref $stack eq "ARRAY"   or $stack = [$stack];

    my $next = $self->app;
    for my $mw (reverse @$stack) {
        $mw = _resolve_mw $mw;
        $next = $mw->($next);
    }

    $self->$on($next);
}

sub _resolve_ace {
    my ($ace) = @_;

    if (blessed $ace) {
        eval { $ace->isa("Plack::Middleware::AuthZ::Base") }
            or croak "Not an AuthZ middleware";
        return $ace;
    }

    my $rt = reftype $ace;
    if ($rt eq "CODE") {
        $ace = [CODE => $ace];
        $rt = "ARRAY";
    }
    if ($rt eq "ARRAY") {
        my ($class, @args) = @$ace;
        $class = Plack::Util::load_class $class, 
            "Plack::Middleware::AuthZ";
        return $class->new(@args);
    }
    croak "Unexpected $rt ref";
}

sub _prepare_acl {
    my ($self) = @_;

    my %on = (
        allow   => $self->on_allow,
        deny    => $self->on_deny,
    );
    
    my $next = $self->app;
    for my $ace (reverse @{$self->acl}) {
        ref $ace or $ace = [split / /, $ace];
        my $action = shift @$ace;

        @$ace or $ace = ["All"];
        $ace = _resolve_ace $ace;

        $ace->on_match($on{$action});
        $ace->wrap($next);
        $next = $ace->to_app;
    }
    $self->on_call($next);
}

sub prepare_app {
    my ($self) = @_;
    
    $self->on_allow or $self->on_allow([]);
    $self->on_deny  or $self->on_deny("Util::Static 401");

    $self->_prepare_stack($_) for "on_allow", "on_deny";
    $self->_prepare_acl;
}

1;
