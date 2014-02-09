use strict;
use warnings;
use MtsoCrypt::Random;

mt_srand(time);

for (0..100) {
    printf "%d\n", mt_rand();
}
