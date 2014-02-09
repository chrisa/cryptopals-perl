package MtsoCrypt::Random;
use strict;
use warnings;
use MtsoCrypt::Random::MT19937;
use base qw/ Exporter /;
our @EXPORT = qw/ random_key
                  random_word
                  mt_srand
                  mt_rand /;

sub random_key {
    join '', map { chr(rand(256)) } (0..15);
}

sub random_word {
    my $selected_word;
    my $count = 0;

    open my $fh, '<', '/usr/share/dict/words'
         or die "Can't read '/usr/share/dict/words': $!\n";

    while (my $word = <$fh>) {
        chomp $word;
        $selected_word = $word if rand ++$count < 1;
    }

    return $selected_word;
}

my $mt;

sub mt_srand {
    my ($seed) = @_;
    $mt ||= MtsoCrypt::Random::MT19937->new;
    $mt->srand($seed);
}

sub mt_rand {
    mt_srand(time) unless defined $mt;
    return $mt->rand;
}

1;
