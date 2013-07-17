use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::XorCipher;
use MtsoCrypt::Metrics;

my $plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
my $key = 'ICE';

my $ciphertext = xor_string($plaintext, $key);
my $hex = encode_hex($ciphertext);
print "$hex\n";

