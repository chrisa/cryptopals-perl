use strict;
use warnings;
use MtsoCrypt::Encoding;

my $hex = '49276d206b696c6c696e6720796f757220627261696e206c' . 
          '696b65206120706f69736f6e6f7573206d757368726f6f6d';
print "$hex\n";

my $base64 = encode_base64(decode_hex($hex));
print "$base64\n";

my $hex2 = encode_hex(decode_base64($base64));
print "$hex2\n";
