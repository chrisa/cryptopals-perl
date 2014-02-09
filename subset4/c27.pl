use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::Modes;
use MtsoCrypt::Random;
use MtsoCrypt::XorCipher;
use Crypt::OpenSSL::AES;

# Encrypt the message under a random key
my $message = 'This message is sure to be at least three blocks long.';
my $ciphertext = encrypt($message);
print STDERR 'original ciphertext: ', encode_hex($ciphertext), "\n";

# Manipulate the ciphertext
my $c1 = substr $ciphertext, 0, 16;
my $mod_ciphertext = $c1 . ("\0" x 16) . $c1;
$mod_ciphertext .= substr $ciphertext, 48;
print STDERR 'modified ciphertext: ', encode_hex($mod_ciphertext), "\n";

my $plaintext;
eval {
    decrypt($mod_ciphertext);
};
if ($@) {
    ($plaintext) = $@ =~ /plaintext: '(.+)'/;
}

if (defined $plaintext) {
    my $p1 = substr $plaintext, 0, 16;
    my $p3 = substr $plaintext, 32, 16;

    my $key = xor_buffers($p1, $p3);
    print STDERR 'recovered key: ', encode_hex($key), "\n";
}

# --------------------------------------------------------------------
# encrypt / decrypt functions under attack

my $key_and_iv;

sub encrypt {
    my ($plaintext) = @_;
    $key_and_iv ||= random_key();
    my $aes = Crypt::OpenSSL::AES->new($key_and_iv);
    return cbc_encrypt(sub { $aes->encrypt($_[0]) }, $key_and_iv, $plaintext);
}

sub decrypt {
    my ($ciphertext) = @_;
    $key_and_iv ||= random_key();
    my $aes = Crypt::OpenSSL::AES->new($key_and_iv);
    # decrypt without padding check
    my $plaintext = cbc_decrypt(sub { $aes->decrypt($_[0]) }, $key_and_iv, $ciphertext, 1);
    unless ($plaintext =~ /^[\x00-\x7f]+$/) {
        die "high-bit characters found in plaintext: '$plaintext'\n";
    }
}

print STDERR ' original key: ', encode_hex($key_and_iv), "\n";
