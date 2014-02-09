use strict;
use warnings;
use MtsoCrypt::Random;
use MtsoCrypt::Modes;
use MtsoCrypt::Encoding;

my $prng = MtsoCrypt::Random::MT19937->new;

my $seed = int(rand(65535));
$prng->srand($seed);

my $plaintext = _random_bytes() . ('A' x 14);
my $ciphertext = prng_stream($prng, $plaintext);

# find 4 characters from the known plaintext aligned on a 4-byte
# boundary.
my $adj = 4 - (((length $ciphertext) - 14) % 4);
my $known_ciphertext = substr $ciphertext, (-14 + $adj), 4;

# convert to a PRNG value
my $prng_bytes = $known_ciphertext ^ 'AAAA';
my $prng_value = unpack('V', $prng_bytes);

# try all 16-bit seeds against the known PRNG value
my $found_seed;
SEED:
for my $try (0..65535) {
    $prng->srand($try);
    for my $i (0..5) {
        if ($prng->rand == $prng_value) {
            $found_seed = $try;
            last SEED;
        }
    }
}

print "seed: $seed\n";
print "found seed: $found_seed\n";

# --------------------------------------------------------------------

sub _random_bytes {
    my $count = 5 + int(rand(5));
    return join '', map { chr(rand(256)) } (1..$count);
}
