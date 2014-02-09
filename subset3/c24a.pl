use strict;
use warnings;
use MtsoCrypt::Random;
use MtsoCrypt::Modes;
use MtsoCrypt::Encoding;

# gen_reset_token uses time() half the time it's called, and a fixed
# number the rest of the time.
#
# see if we can discriminate:

for (0..100) {
    my $user = 'fred12345';
    my ($token, $seed) = gen_reset_token($user);
    printf "%d %s\n", $seed, is_time_seeded($token, $user) ? 'yes' : 'no', "\n";
}

# --------------------------------------------------------------------

sub is_time_seeded {
    my ($token, $user) = @_;

    # find 4 characters from the known plaintext and ciphertext,
    # aligned on a 4-byte boundary.
    my $len = length $user;
    my $adj = 4 - (((length $token) - $len) % 4);
    my $known_ciphertext = substr $token, (-$len + $adj), 4;
    my $known_plaintext = substr $user, (-$len + $adj), 4;

    # convert to a PRNG value
    my $prng_bytes = $known_ciphertext ^ $known_plaintext;
    my $prng_value = unpack('V', $prng_bytes);

    my $found_seed;
    my $time = time();

    # try from 10s before now, up until now.
 SEED:
    for my $try ($time - 10..$time) {
        my $prng = MtsoCrypt::Random::MT19937->new;
        $prng->srand($try);

        # make sure we try enough values for the length of the string
        my $tries = (length $token) / 4;
        for (0..$tries) {
            if ($prng->rand == $prng_value) {
                $found_seed = $try;
                last SEED;
            }
        }
    }

    if (defined $found_seed) {
        return 1;
    }
    return;
}

# --------------------------------------------------------------------

sub gen_reset_token {
    my ($user_id) = @_;

    my $prng = MtsoCrypt::Random::MT19937->new;
    my $seed = (rand(1) < 0.5) ? time() : 1111111111;
    $prng->srand($seed);

    # create a reset token with:
    # * some fixed bytes
    # * some random bytes
    # * the time
    # * the user id

    my $plaintext = sprintf 'reset_token_%s_%9d_%s',
         _random_bytes(), time(), $user_id;

    my $ciphertext = prng_stream($prng, $plaintext);

    return ($ciphertext, $seed);
}

sub _random_bytes {
    my $count = 50 + int(rand(5));
    return join '', map { chr(rand(256)) } (1..$count);
}
