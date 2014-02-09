use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::Modes;
use MtsoCrypt::Random;
use Crypt::OpenSSL::AES;
use List::Util qw / shuffle /;

my @ciphertexts = map { decode_base64($_) } <DATA>;

for (1..100) {
    my ($ciphertext, $iv) = encrypt();
    print decrypt_string($ciphertext, $iv), "\n";
}

# --------------------------------------------------------------------

sub decrypt_string {
    my ($ciphertext, $iv) = @_;

    my $blocks = length($ciphertext) / 16;
    my @blocks = unpack 'A16' x $blocks, $ciphertext;
    unshift @blocks, $iv;

    my $plaintext = '';
    for my $i (0..($blocks-1)) {
        $plaintext .= decrypt_block($blocks[$i], $blocks[$i+1]);
    }
    return unpad_pkcs7($plaintext);
}

sub decrypt_block {
    my ($block1, $block2) = @_;
    my @chars;

    for (my $byte = 15; $byte >= 0; $byte--) {
        for my $i (0..255) {
            my ($edit, $target) = ($block1, $block2);

            for (my $offset = 15; $offset >= $byte; $offset--) {
                if ($offset > $byte) {
                    my $padchar = $chars[$offset] ^ chr(16 - $byte);
                    substr($edit, $offset, 1) ^= $padchar;
                }
                else {
                    substr($edit, $offset, 1) ^= chr($i);
                }
            }

            my $plaintext;
            eval { decrypt($target, $edit) };
            next if ($@);

            $chars[$byte] = chr($i) ^ chr(16 - $byte);
        }
    }

    my $plaintext = '';
    for my $byte (0..15) {
        $plaintext .= (defined $chars[$byte] ? $chars[$byte] : ' ');
    }
    return $plaintext;
}

# --------------------------------------------------------------------

my $key;

sub encrypt {
    my @shuffled = shuffle @ciphertexts;
    my $plaintext = $shuffled[0];

    $key ||= random_key();
    my $iv = random_key();
    my $aes = Crypt::OpenSSL::AES->new($key);

    return (cbc_encrypt(sub { $aes->encrypt($_[0]) }, $iv, $plaintext), $iv);
}

sub decrypt {
    my ($ciphertext, $iv) = @_;

    $key ||= random_key();
    my $aes = Crypt::OpenSSL::AES->new($key);

    return cbc_decrypt(sub { $aes->decrypt($_[0]) }, $iv, $ciphertext);
}

__DATA__
MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
