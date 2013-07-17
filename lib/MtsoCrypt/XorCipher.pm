package MtsoCrypt::XorCipher;
use strict;
use warnings;
use POSIX qw/ ceil /;
use base qw/ Exporter /;
our @EXPORT = qw/ xor_buffers 
                  xor_character
                  xor_string /;

sub xor_buffers {
    my ($s1, $s2) = @_;
    return "$s1" ^ "$s2";
}

sub xor_character {
    my ($buf, $char) = @_;
    my $string = $char x length $buf;
    return xor_buffers($buf, $string);
}

sub xor_string {
    my ($buf, $string) = @_;
    my $repeats = ceil(length($buf) / length($string));
    my $string2 = $string x $repeats;
    $string2 = substr $string2, 0, length $buf;
    return xor_buffers($buf, $string2);
}

1;
