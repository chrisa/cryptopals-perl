use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::XorCipher;

my $string = '1c0111001f010100061a024b53535009181c';
my $key = '686974207468652062756c6c277320657965';

my $result = encode_hex(xor_buffers(decode_hex($string), decode_hex($key)));
print "$result\n";
