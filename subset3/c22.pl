use strict;
use warnings;
use MtsoCrypt::Random;

my $time = time();
mt_srand($time);

my $rand = mt_rand();

for (my $seed = ($time + 1000); $seed > 0; $seed--) {
    mt_srand($seed);
    if (mt_rand() == $rand) {
        print "seed seems to be: $seed (and actually was: $time)\n";
        last;
    }
}
