use strict;
use warnings;
use MtsoCrypt::Encoding;

my $valid = "ICE ICE BABY\x04\x04\x04\x04";
my $invalid1 = "ICE ICE BABY\x05\x05\x05\x05";
my $invalid2 = "ICE ICE BABY\x01\x02\x03\x04";

print unpad_pkcs7($valid), "\n";

eval { print unpad_pkcs7($invalid1), "\n" };
print $@;

eval { print unpad_pkcs7($invalid2), "\n" };
print $@;
