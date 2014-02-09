use strict;
use warnings;
use LWP::UserAgent;
use Time::HiRes;
use List::Util qw/ min max sum /;
use List::MoreUtils qw/ pairwise uniq /;
use Data::Dumper;
use MtsoCrypt::Encoding;

# expects to have the app.pl server running on localhost:3000, with an
# argument of "0.005".

my $url = 'http://localhost:3000/test';
my $file ='foo';

# --------------------------------------------------------------------------

# warm up the resolver cache - or we fairly predictably choose the
# first byte tried as the longest.

my ($result, $time) = request($file, 'random bad guess');

# for each byte, start by trying all 256 bytes, then repeatedly retry
# the top 20 bytes, keeping hold of all times for this byte until a
# clear modal byte emerges.

my @all = (0..255);
my $signature = '';
for my $i (0..19) {
    my @bytes = @all;
    my @times;

 ATTEMPT:
    for (;;) {
        printf STDERR "trying %d bytes...\n", scalar @bytes;

        push @times, @{ get_byte_times($signature, \@bytes) };
        @times = sort { $b->[0] <=> $a->[0] } @times;

        for my $time (@times[0..19]) {
            printf STDERR "guess: %x time: %0.4f\n", $time->[1], $time->[0];
        }

        my $byte = mode(map { $_->[1] } @times[0..19]);
        if (defined $byte) {
            $signature .= chr($byte);
            printf STDERR "Progress: %s\n\n", encode_hex($signature);
            last ATTEMPT;
        }
        else {
            @bytes = uniq map { $_->[1] } @times[0..31];
            shift @times if rand > 0.7;
        }

        print STDERR "\n";
    }
}

print STDERR "signature: $signature\n";

# return an arrayref of arrayrefs with time/byte pairs, for the bytes
# given in the arrayref.

sub get_byte_times {
    my ($base, $bytes) = @_;
    my @times;
    for my $byte (@$bytes) {
        my $guess = $base . (chr($byte) x (20 - length $base));
        my (undef, $time) = request($file, encode_hex($guess));
        push @times, [$time, $byte];
    }
    return \@times;
}

# --------------------------------------------------------------------------

sub request {
    my ($file, $signature) = @_;
    my $ua = LWP::UserAgent->new;
    my $start = [ Time::HiRes::gettimeofday ];
    my $response = $ua->get($url . "?file=$file&signature=$signature");
    my $time = Time::HiRes::tv_interval($start, [ Time::HiRes::gettimeofday ]);
    return $response->is_success ? 1 : 0, $time;
}

# compute the mode of the values given, returning it only if it
# represents more than half of the set

sub mode {
    my %values;
    $values{$_}++ for @_;
    my %counts = reverse %values;
    my $mode = $counts{max(keys %counts)};
    printf STDERR "mode: %x mode count: %d total count: %d\n\n", $mode, $values{$mode}, scalar(@_);
    return ($values{$mode} > (scalar(@_) / 2)) ? $mode : undef;
}
