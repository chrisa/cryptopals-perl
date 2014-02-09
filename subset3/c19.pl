use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::Modes;
use MtsoCrypt::Random;
use MtsoCrypt::Metrics;
use MtsoCrypt::XorCipher;
use Crypt::OpenSSL::AES;
use List::Util qw/ min max sum /;

my @base64 = qw( SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
                 Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
                 RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
                 RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
                 SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
                 T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
                 T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
                 UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
                 QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
                 T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
                 VG8gcGxlYXNlIGEgY29tcGFuaW9u
                 QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
                 QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
                 QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
                 QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
                 QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
                 VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
                 SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
                 SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
                 VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
                 V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
                 V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
                 U2hlIHJvZGUgdG8gaGFycmllcnM/
                 VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
                 QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
                 VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
                 V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
                 SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
                 U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
                 U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
                 VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
                 QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
                 SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
                 VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
                 WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
                 SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
                 SW4gdGhlIGNhc3VhbCBjb21lZHk7
                 SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
                 VHJhbnNmb3JtZWQgdXR0ZXJseTo=
                 QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4= );

my @plaintexts = map { decode_base64($_) } @base64;

my $key = random_key();
my $aes = Crypt::OpenSSL::AES->new($key);
my $nonce = "\x00" x 8;

my @ciphertexts;
for my $plaintext (@plaintexts) {
    my $ciphertext = ctr_stream($aes, $nonce, $plaintext);
    push @ciphertexts, $ciphertext;
}

# Find a keystream by trying trigrams against the first ciphertext,
# using the key each produces on all the other ciphertexts, then
# choosing the most likely key by looking for the key which produces
# the most English-like group of characters.

my $length = min map { length($_) } @ciphertexts;
my $keystream = '';
my $scores;

for my $i (0..($length - 3)) {
    my $triplet = substr $ciphertexts[0], $i, 3;
    for my $root (all_trigrams()) {
        my $key = xor_buffers($triplet, lc $root);
        my $buffer = '';
        for my $ciphertext (@ciphertexts) {
            $buffer .= xor_buffers($key, substr($ciphertext, $i, 3));
        }

        #my $score = freq_score(character_freqs($buffer));
        my $score = trigram_score($buffer);

        # record the score per character offset; we'll use the best
        # score for each offset regardless of which triplet it came
        # from.
        if (!exists $scores->{$i} || $score > $scores->{$i}->[0]) {
            $scores->{$i + $_} = [$score, substr $key, $_, 1] for (0..2);
        }
    }

    $keystream .= substr $scores->{$i}->[1], 0, 1;
}

for my $ciphertext (@ciphertexts) {
    $ciphertext = substr $ciphertext, 0, (length $keystream);
    my $plaintext = xor_buffers($keystream, $ciphertext);
    print "$plaintext\n";
}
