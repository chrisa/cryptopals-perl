use strict;
use warnings;
use LWP::UserAgent;
use Time::HiRes;
use List::Util qw/ min max sum /;
use List::MoreUtils qw/ pairwise /;
use Data::Dumper;
use MtsoCrypt::Encoding;

# expects to have the app.pl server running on localhost:3000, with an
# argument of "0.05".

my $url = 'http://localhost:3000/test';
my $file ='foo';

# --------------------------------------------------------------------------

# warm up the resolver cache - or we fairly predictably choose the
# first byte tried as the longest.

my ($result, $time) = request($file, 'random bad guess');

# for each byte position, find the byte which takes the longest to
# return.

my $signature = '';
for my $i (0..19) {
    my @times;
    for my $byte (0..255) {
        my $guess = $signature . (chr($byte) x (20 - length $signature));
        my (undef, $time) = request($file, encode_hex($guess));
        printf STDERR "guess: %s time: %0.4f\n", encode_hex($guess), $time;
        push @times, [$time, $byte];
    }
    @times = sort { $b->[0] <=> $a->[0] } @times;
    $signature .= chr($times[0]->[1]);
    printf STDERR "%s\n", encode_hex($signature);
}

print STDERR "signature: $signature\n";

# --------------------------------------------------------------------------

sub request {
    my ($file, $signature) = @_;
    my $ua = LWP::UserAgent->new;
    my $start = [ Time::HiRes::gettimeofday ];
    my $response = $ua->get($url . "?file=$file&signature=$signature");
    my $time = Time::HiRes::tv_interval($start, [ Time::HiRes::gettimeofday ]);
    return $response->is_success ? 1 : 0, $time;
}
