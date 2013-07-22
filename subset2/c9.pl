use strict;
use warnings;
use MtsoCrypt::Encoding;

my $plaintext = 'YELLOW SUBMARINE';

my $padded = pad_pkcs7($plaintext, 20);
my $hex = encode_hex($padded);

print "$hex\n";
