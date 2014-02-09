use strict;
use warnings;
use Data::Dumper;

use MtsoCrypt::Mac;
use MtsoCrypt::Hash;
use MtsoCrypt::Random;
use MtsoCrypt::Encoding;

my $message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon';
my $admin = ';admin=true';
my $key = random_word();

# MAC the original message with the key
my $mac = keyed_mac(\&my_md4, $key, $message);

for my $key_length (2..20) {
    my ($glue, $forged_mac) = forge_mac($mac, $admin, $key_length);
    my $admin_mac = keyed_mac(\&my_md4, $key, ($message . $glue . $admin));
    if ($admin_mac eq $forged_mac) {
        printf STDERR "  key length: %d\n", $key_length;
        printf STDERR "original MAC: %s\n", encode_hex($mac);
        printf STDERR "   admin MAC: %s\n", encode_hex($admin_mac);
        printf STDERR "  forged MAC: %s\n", encode_hex($forged_mac);
        last;
    }
}

# --------------------------------------------------------------------------

sub forge_mac {
    my ($mac, $extension, $key_length) = @_;

    # Construct the glue padding
    my $glue = md_padding(('A' x $key_length) . $message);

    # add up the "fake length" in bits
    my $fake_len = ($key_length + length($message) + length($glue) + length($admin)) << 3;

    # retrieve the SHA1 registers and length-extend
    my @regs = unpack("V4", $mac);
    my $forged_mac = my_md4($admin, $fake_len, @regs);

    return ($glue, $forged_mac);
}

sub md_padding {
    my ($message) = @_;
    my $bit_len = (length $message) << 3; # bit length of message

    # get down to the last two blocks
    while (length $message > 64) {
        substr $message, 0, 64, '';
    }
    my $len = length $message;

    my $padding = '';

    # pad second-last block if necessary
    if (length $message > 55) {
        $padding .= "\x80";
        $padding .= "\0" x (63 - $len);
        $len = 0;
    }

    # pad last block
    $padding .= (length $padding > 0) ? "\0" : "\x80";
    $padding .= "\0" x (55 - $len);
    $padding .= pack("V2", ($bit_len & 0xffffffff), ($bit_len >> 32));

    return $padding;
}
