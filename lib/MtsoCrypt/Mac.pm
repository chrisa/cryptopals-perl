package MtsoCrypt::Mac;
use strict;
use warnings;
use MtsoCrypt::XorCipher;
use base qw/ Exporter /;
our @EXPORT = qw/ keyed_mac
                  auth_keyed_mac
                  hmac
                /;

sub keyed_mac {
    my ($hash, $key, $message) = @_;
    return $hash->($key . $message);
}

sub auth_keyed_mac {
    my ($hash, $key, $message, $mac) = @_;
    return $mac eq $hash->($key . $message);
}

sub hmac {
    my ($hash, $key, $message) = @_;

    if (length($key) > 64) {
        $key = $hash->($key);
    }
    if (length($key) < 64) {
        $key = $key . ("\0" x (64 - length($key)));
    }

    my $o_key_pad = xor_buffers(("\x5c" x 64), $key);
    my $i_key_pad = xor_buffers(("\x36" x 64), $key);

    return $hash->($o_key_pad . $hash->($i_key_pad . $message));
}

1;
