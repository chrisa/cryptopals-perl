use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::Modes;
use MtsoCrypt::Random;
use MtsoCrypt::Metrics;
use Crypt::OpenSSL::AES;

# --------------------------------------------------------------------
# detect block size

my $prev_ciphertext;
my $blocksize;
for (my $bs = 1; $bs < 40; $bs++) {
    my $plaintext = 'A' x $bs;
    my $ciphertext = encryption_oracle($plaintext);

    # if we've reached the blocksize plus 1, the current first block
    # of ciphertext will match the previous first block.

    if ($prev_ciphertext) {
        my $block = substr($ciphertext, 0, $bs - 1);
        my $prev_block = substr($prev_ciphertext, 0, $bs - 1);

        if ($block eq $prev_block) {
            $blocksize = $bs - 1;
            last;
        }
    }
    $prev_ciphertext = $ciphertext;
}
print "blocksize is $blocksize\n";

# --------------------------------------------------------------------
# detect ECB

my $plaintext = 'x' x 100;
my $ciphertext = encryption_oracle($plaintext);
my $blocks;
for (my $offset = 0; $offset < length($ciphertext); $offset += 16) {

    # if we see two blocks the same in a long ciphertext encrypting a
    # repeating single-byte plaintext, the mode is ECB.

    my $block = substr $ciphertext, $offset, 16;
    if ($blocks->{$block}++) {
        print "ECB encryption detected\n";
        last;
    }
}

# --------------------------------------------------------------------
# decrypt ECB-mode AES

my $prefix = 'A' x 255;
$plaintext = '';
while (length $prefix) {
    my $short = substr encryption_oracle($prefix), 0, 256;

    my $encrypts;
    for my $i (0..255) {
        my $input = $prefix . $plaintext . chr($i);
        my $output = encryption_oracle($input);
        $encrypts->{substr($output, 0, 256)} = $i;
    }
    last unless exists $encrypts->{$short};

    $plaintext .= chr($encrypts->{$short});
    chop $prefix;
}
print "$plaintext\n";

# --------------------------------------------------------------------
# oracle function

my $key;

sub encryption_oracle {
    my ($plaintext) = @_;
    $key ||= random_key();
    my $aes = Crypt::OpenSSL::AES->new($key);

    my $base64 =
         'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' . 
         'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' .
         'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' .
         'YnkK';

    $plaintext = $plaintext . decode_base64($base64);

    return ecb_encrypt(sub { $aes->encrypt($_[0]) }, $plaintext);
}

