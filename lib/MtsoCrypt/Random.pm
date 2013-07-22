package MtsoCrypt::Random;
use strict;
use warnings;
use base qw/ Exporter /;
our @EXPORT = qw/ random_key /;

sub random_key {
    join '', map { chr(rand(256)) } (0..15);
}
