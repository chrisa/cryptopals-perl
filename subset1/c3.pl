use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::XorCipher;
use MtsoCrypt::Metrics;

my $ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736';

my $decrypts;

for my $i (0..255) {
    my $char = chr($i);
    my $plaintext = xor_character(decode_hex($ciphertext), $char);
    my $freqs = character_freqs($plaintext);
    
    if (scalar keys %$freqs) {
        my $score = freq_score($freqs);
        $decrypts->{$plaintext} = [$score, $char];
    }
}

my @decrypts = sort { $decrypts->{$a}->[0] <=> $decrypts->{$b}->[0] } keys %$decrypts;
print "key: $decrypts->{$decrypts[0]}->[1]\n";
print "$decrypts[0]\n";
