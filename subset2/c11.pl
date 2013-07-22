use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::Modes;
use MtsoCrypt::Random;
use Crypt::OpenSSL::AES;

my ($ecbs, $cbcs, $ecbs_detected) = (0, 0, 0);

# choose a plaintext composed of a single byte long enough to
# guarantee that however much random padding is applied, there will be
# at least two blocks entirely of our plaintext -- in order that we
# can detect ECB mode by the simple "duplicate blocks" technique.

my $plaintext = 'x' x 50;

for (1..1000) {
    my $ciphertext = encryption_oracle($plaintext);
    
    my $blocks;
    for (my $offset = 0; $offset < length($ciphertext); $offset += 16) {
        my $block = substr $ciphertext, $offset, 16;
        if ($blocks->{$block}++) {
            $ecbs_detected++;
            last;
        }
    }
}

print "ecbs: $ecbs cbcs: $cbcs\n";
print "ecbs detected: $ecbs_detected\n";

# --------------------------------------------------------------------

sub encryption_oracle {
    my ($plaintext) = @_;
    my $key = random_key();
    my $aes = Crypt::OpenSSL::AES->new($key);

    $plaintext = _random_bytes() . $plaintext . _random_bytes();

    if (rand() > 0.5) {
        $ecbs++;
        return ecb_encrypt(sub { $aes->encrypt($_[0]) }, $plaintext);
    }
    else {
        $cbcs++;
        my $iv = random_key();
        return cbc_encrypt(sub { $aes->encrypt($_[0]) }, $iv, $plaintext);
    }
}

sub _random_bytes {
    my $count = 5 + int(rand(5));
    return join '', map { chr(rand(256)) } (1..$count);
}
