use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::Modes;
use MtsoCrypt::Random;
use MtsoCrypt::Metrics;
use Crypt::OpenSSL::AES;

# --------------------------------------------------------------------
# detect block size

my $blocksize;

BS:
for (my $len = 12; $len < 120; $len += 1) {
    my $plaintext = 'A' x $len;
    my $ciphertext = encryption_oracle($plaintext);

    # Look for a pair of consecutive blocks, starting from a block
    # length a third the length of the string we gave to the oracle --
    # to make sure that there will be at least two full blocks of our
    # fixed string in the ciphertext, regardless of the length of the
    # random prefix

    for (my $bs = int($len/3); $bs < 80; $bs++) {
        my $blocks;
        for (my $offset = 0; $offset < length($ciphertext); $offset += $bs) {
            if ($blocks->{substr($ciphertext, $offset, $bs)}) {
                $blocksize = $bs;
                last BS;
            }
            $blocks->{substr($ciphertext, $offset, $bs)}++;
        }
    }
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

# We can only make progress in the decryption when we know where our
# string is located in the ciphertext. To do that, we create two
# different sentinel strings of two blocks each. If we see two pairs
# of blocks, that will be our string, and the following block is our
# prefix.

my $prefix = ('A' x 32) . ('B' x 32) . ('C' x 255);

# This algorithm is the same as the example without a random prefix,
# except that instead of a single encryption, we call our function to
# invoke the oracle function repeatedly until it can locate the
# ciphertext we need.

$plaintext = '';

while (length $prefix) {
    my $short = encrypt_until_located($prefix);

    my $encrypts;
    for my $i (0..255) {
        my $input = $prefix . $plaintext . chr($i);
        my $output = encrypt_until_located($input);
        $encrypts->{$output} = chr($i);
    }
    last unless exists $encrypts->{$short};

    $plaintext .= $encrypts->{$short};
    chop $prefix;
}
print "$plaintext\n";

# function to repeatedly invoke the oracle function until it can
# locate our sentinel blocks on a block boundary, and from there
# extract the relevant ciphertext. 

sub encrypt_until_located {
    my ($plaintext) = @_;
    my $located;

    while (1) {
        my $ciphertext = encryption_oracle($plaintext);

        my @blocks = unpack 'A16' x 5, $ciphertext;

        # We hope to find our sentinel blocks as the second through
        # fifth blocks - if so, return 256 bytes from the start of the
        # sixth block.

        if ($blocks[1] eq $blocks[2] && $blocks[3] eq $blocks[4]) {
            return substr($ciphertext, 80, 256);
        }
    }
}

# --------------------------------------------------------------------
# oracle function

my $key;

sub encryption_oracle {
    my ($plaintext) = @_;
    $key ||= random_key();
    my $aes = Crypt::OpenSSL::AES->new($key);

    my $prefix = join '', map { chr(rand(256)) } (0..(int(rand(16))));

    my $base64 =
         'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' . 
         'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' .
         'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' .
         'YnkK';

    $plaintext = $prefix . $plaintext . decode_base64($base64);

    return ecb_encrypt(sub { $aes->encrypt($_[0]) }, $plaintext);
}

