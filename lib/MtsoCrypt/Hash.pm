package MtsoCrypt::Hash;
use strict;
use warnings;
use MtsoCrypt::Encoding;

use base qw/ Exporter /;
our @EXPORT = qw/ my_sha1
                  my_md4 /;

# This is the RosettaCode *Ruby* SHA1, transliterated into Perl. I
# couldn't find a Perl5 SHA1 that wasn't transliterated from C and bad
# for fiddling with.

sub my_sha1 {
    my ($string, $bit_len, $fix_a, $fix_b, $fix_c, $fix_d, $fix_e) = @_;

    # functions and constants
    my $mask = (1 << 32) - 1;        # ffffffff
    my $s = sub { my ($n, $x) = @_; (($x << $n) & $mask) | ($x >> (32 - $n))};
    my @f = (
        sub { my ($b, $c, $d) = @_; ($b & $c) | ($b ^ $mask) & $d },
        sub { my ($b, $c, $d) = @_; $b ^ $c ^ $d },
        sub { my ($b, $c, $d) = @_; ($b & $c) | ($b & $d) | ($c & $d) },
        sub { my ($b, $c, $d) = @_; $b ^ $c ^ $d },
    );
    my @k = (0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6);

    # initial hash with optional fixation
    my @h = (
        $fix_a || 0x67452301,
        $fix_b || 0xefcdab89,
        $fix_c || 0x98badcfe,
        $fix_d || 0x10325476,
        $fix_e || 0xc3d2e1f0
    );

    my $term = 0;  # appended "\x80" in second-last block?
    my $last = 0;  # last block?
    $bit_len //= (length $string) << 3; # bit length of string

    while (!$last) {
        # Read next block of 16 words (64 bytes, 512 bits).
        my $block = substr $string, 0, 64, '';

        # Unpack block into 32-bit words "N".
        my $len = length $block;
        my @w;
        if ($len == 64) {
            # Unpack 16 words.
            @w = unpack("N16", $block);
        }
        if ($len >= 56 && $len <= 63) {
            # Second-last block: append padding, unpack 16 words.
            $block .= "\x80";
            $term = 1;
            $block .= "\0" x (63 - $len);
            @w = unpack("N16", $block);
        }
        if ($len <= 55) {
            # Last block: append padding, unpack 14 words.
            $block .= $term ? "\0" : "\x80";
            $block .= "\0" x (55 - $len);

            # Append bit length, 2 words.
            $block .= pack("N2", ($bit_len >> 32), ($bit_len & $mask));

            @w = unpack("N16", $block);
            $last = 1;
        }

        # Process block.
        for my $t (16..79) {
            $w[$t] = $s->(1, $w[$t-3] ^ $w[$t-8] ^ $w[$t-14] ^ $w[$t-16]);
        }

        my ($a, $b, $c, $d, $e) = @h;
        my $t = 0;
        for my $i (0..3) {
            for (0..19) {
                my $temp = ($s->(5, $a) + $f[$i]->($b, $c, $d) + $e + $w[$t] + $k[$i]) & $mask;
                ($a, $b, $c, $d, $e) = ($temp, $a, $s->(30, $b), $c, $d);
                $t++;
            }
        }

        $h[0] = ($h[0] + $a) & $mask;
        $h[1] = ($h[1] + $b) & $mask;
        $h[2] = ($h[2] + $c) & $mask;
        $h[3] = ($h[3] + $d) & $mask;
        $h[4] = ($h[4] + $e) & $mask;
    }

    return pack "N5", @h;
}

# Again, this is the RosettaCode *Ruby* MD4, transliterated into
# Perl.

sub my_md4 {
    my ($string, $bit_len, $fix_a, $fix_b, $fix_c, $fix_d) = @_;

    # functions
    my $mask = (1 << 32) - 1;        # ffffffff

    my $f = sub { my ($x, $y, $z) = @_; $x & $y | ($x ^ $mask) & $z };
    my $g = sub { my ($x, $y, $z) = @_; $x & $y | $x & $z | $y & $z };
    my $h = sub { my ($x, $y, $z) = @_; $x ^ $y ^ $z };
    my $r = sub { my ($v, $s) = @_; (($v << $s) & $mask) | (($v & $mask) >> (32 - $s)) };

    # initial hash
    my ($a, $b, $c, $d) = (
        $fix_a || 0x67452301,
        $fix_b || 0xefcdab89,
        $fix_c || 0x98badcfe,
        $fix_d || 0x10325476
    );

    my $term = 0;  # appended "\x80" in second-last block?
    my $last = 0;  # last block?
    $bit_len //= (length $string) << 3; # bit length of string

    while (!$last) {
        # Read next block of 16 words (64 bytes, 512 bits).
        my $block = substr $string, 0, 64, '';

        # Unpack block into 32-bit words "N".
        my $len = length $block;
        my @w;
        if ($len == 64) {
            # Unpack 16 words.
            @w = unpack("V16", $block);
        }
        if ($len >= 56 && $len <= 63) {
            # Second-last block: append padding, unpack 16 words.
            $block .= "\x80";
            $term = 1;
            $block .= "\0" x (63 - $len);
            @w = unpack("V16", $block);
        }
        if ($len <= 55) {
            # Last block: append padding, unpack 14 words.
            $block .= $term ? "\0" : "\x80";
            $block .= "\0" x (55 - $len);

            # Append bit length, 2 words.
            $block .= pack("V2", ($bit_len & $mask), ($bit_len >> 32)); # reverse order to SHA1!

            @w = unpack("V16", $block);
            $last = 1;
        }

        # Process this block.
        my ($aa, $bb, $cc, $dd) = ($a, $b, $c, $d);

        for my $i (0, 4, 8, 12) {
            my $j = $i;
            $a = $r->($a + $f->($b, $c, $d) + $w[$j],  3); $j += 1;
            $d = $r->($d + $f->($a, $b, $c) + $w[$j],  7); $j += 1;
            $c = $r->($c + $f->($d, $a, $b) + $w[$j], 11); $j += 1;
            $b = $r->($b + $f->($c, $d, $a) + $w[$j], 19);
        }
        for my $i (0, 1, 2, 3) {
            my $j = $i;
            $a = $r->($a + $g->($b, $c, $d) + $w[$j] + 0x5a827999,  3); $j += 4;
            $d = $r->($d + $g->($a, $b, $c) + $w[$j] + 0x5a827999,  5); $j += 4;
            $c = $r->($c + $g->($d, $a, $b) + $w[$j] + 0x5a827999,  9); $j += 4;
            $b = $r->($b + $g->($c, $d, $a) + $w[$j] + 0x5a827999, 13);
        }
        for my $i (0, 2, 1, 3) {
            my $j = $i;
            $a = $r->($a + $h->($b, $c, $d) + $w[$j] + 0x6ed9eba1,  3); $j += 8;
            $d = $r->($d + $h->($a, $b, $c) + $w[$j] + 0x6ed9eba1,  9); $j -= 4;
            $c = $r->($c + $h->($d, $a, $b) + $w[$j] + 0x6ed9eba1, 11); $j += 8;
            $b = $r->($b + $h->($c, $d, $a) + $w[$j] + 0x6ed9eba1, 15);
        }
        $a = ($a + $aa) & $mask;
        $b = ($b + $bb) & $mask;
        $c = ($c + $cc) & $mask;
        $d = ($d + $dd) & $mask;
    }

    return pack("V4", $a, $b, $c, $d);
}

1;
