package MtsoCrypt::HmacApp;
use strict;
use warnings;
use MtsoCrypt::Random;
use MtsoCrypt::Mac;
use MtsoCrypt::Encoding;
use MtsoCrypt::Hash;
use Digest::SHA qw/ sha1 /;

use Dancer ':syntax';

my $key = random_key();
my $delay = $ARGV[0] || '0.05'; # seconds to sleep

printf STDERR "%s\n", encode_hex(hmac(\&my_sha1, $key, 'foo'));

sub insecure_compare {
    my ($left, $right) = @_;
    return 0 if length $left != length $right;

    for my $i (0..(length $left)-1) {
        return 0 if substr($left, $i, 1) ne substr($right, $i, 1);
        select undef, undef, undef, $delay;
    }

    return 1;
}

get '/test' => sub {
    my $signature = hmac(\&my_sha1, $key, params->{file});
    if (insecure_compare($signature, decode_hex(params->{signature}))) {
        return "OK\n";
    }
    else {
        die "NOT OK\n";
    }
};

1;
