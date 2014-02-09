use strict;
use warnings;
use MtsoCrypt::Random;
use MtsoCrypt::Util;

my @values = map { mt_rand() } (0..623);
my @state = map { untemper($_) } @values;

# get ourselves a new MT instance, and inject the original instance's
# state:
my $mt = MtsoCrypt::Random::MT19937->new;
$mt->{MT} = [@state];

# check that the output from both matches from this point:
my $differences = 0;
for my $i (0..100000) {
    my ($source, $target) = (mt_rand(), $mt->rand);
    printf "%15d %15d %s\n", $source, $target, ($source != $target) ? '<===' : '';
    $differences++ if $source != $target;
}
print "Differences: $differences\n";

# --------------------------------------------------------------------

sub untemper {
    my ($y) = @_;
    $y = unshiftxor_right($y, 18);
    $y = unshiftxormask_left($y, 15, 4022730752);
    $y = unshiftxormask_left($y, 7, 2636928640);
    $y = unshiftxor_right($y, 11);
    return $y;
}

sub unshiftxor_right {
    my ($value, $shift) = @_;
    my $result = 0;

    for (my $i = 0; $i < 32; $i += $shift) {
        my $mask = 0;
        for (my $j = (31 - $i); $j >=0 && $j > (31 - $i - $shift); $j--) {
            $mask += 2**$j;
        }
        my $part = $value & $mask;
        $value ^= $part >> $shift;
        $result |= $part;
    }

    return $result;
}

sub unshiftxormask_left {
    my ($value, $shift, $maskval) = @_;
    my $result = 0;

    for (my $i = 0; $i < 32; $i += $shift) {
        my $mask = 0;
        for (my $j = $i; $j < 32 && $j < ($i + $shift); $j++) {
            $mask += 2**$j;
        }
        my $part = $value & $mask;
        $value ^= (($part << $shift) & $maskval);
        $result |= $part;
    }

    return $result;
}
