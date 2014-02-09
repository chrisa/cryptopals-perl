package MtsoCrypt::Util;
use strict;
use warnings;
use MtsoCrypt::Encoding;
use base qw/ Exporter /;
our @EXPORT = qw/ print_by_blocks
                  print_by_blocks_hex
                  print_by_blocks_bin /;

sub print_by_blocks {
    my ($text) = @_;
    for (my $i = 0; $i < length $text; $i += 16) {
        printf "%s\n", substr($text, $i, 16);
    }
    print "\n";
}

sub print_by_blocks_hex {
    my ($text) = @_;
    $text = encode_hex($text);
    for (my $i = 0; $i < length $text; $i += 32) {
        printf "%s\n", substr($text, $i, 32);
    }
    print "\n";
}

sub print_by_blocks_bin {
    my ($text) = @_;
    $text = encode_hex($text);
    for (my $i = 0; $i < length $text; $i += 4) {
        my $block = substr($text, $i, 4);
        printf "%s\n", join '', map { vec $block, $_, 1 } (0..32);
    }
    print "\n";
}

1;
