package MtsoCrypt::Metrics;
use strict;
use warnings;
use List::Util qw/ sum /;
use base qw/ Exporter /;
our @EXPORT = qw/ character_freqs
                  freq_score
                  hamming_distance /;

sub character_freqs {
    my ($string) = @_;
    
    my @characters = split '', $string;

    my $freqs;
    for my $char (@characters) {
        $freqs->{$char}++;
    }
    
    for my $char (keys %$freqs) {
        $freqs->{$char} /= scalar @characters;
        $freqs->{$char} *= 100;
    }

    return $freqs;
}

sub freq_score {
    my ($freqs) = @_;

    # english letter frequencies in percent, source:
    # http://en.wikipedia.org/wiki/Letter_frequency

    my $english = {
        'e' => 12.702, 
        't' => 9.056, 
        'a' => 8.167, 
        'o' => 7.507, 
        'i' => 6.966, 
        'n' => 6.749, 
        's' => 6.327, 
        'h' => 6.094, 
        'r' => 5.987, 
        'd' => 4.253, 
        'l' => 4.025, 
        'c' => 2.782, 
        'u' => 2.758, 
        'm' => 2.406, 
        'w' => 2.360, 
        'f' => 2.228, 
        'g' => 2.015, 
        'y' => 1.974, 
        'p' => 1.929, 
        'b' => 1.492, 
        'v' => 0.978, 
        'k' => 0.772, 
        'j' => 0.153, 
        'x' => 0.150, 
        'q' => 0.095, 
        'z' => 0.074
    };

    # scoring:
    # 
    # total of the differences between the sample and english, per letter,
    # plus the total of the percentages of non-letter characters
    #
    # lower is better.

    my $score = 0;
    for my $letter (keys %$english) {
        $score += abs(($freqs->{$letter} || 0) - $english->{$letter});
    }
    for my $character (keys %$freqs) {
       if (!exists $english->{$character}) {
           $score += $freqs->{$character};
       }
    }
    
    return $score;
}

sub hamming_distance {
    my ($s1, $s2) = @_;
    my $bits = "$s1" ^ "$s2";
    return sum(map { vec($bits, $_, 1) } 0..(length($bits) * 8) - 1);
}

1;
