package MtsoCrypt::Modes;
use strict;
use warnings;
use MtsoCrypt::XorCipher;
use MtsoCrypt::Encoding;
use MtsoCrypt::Util;
use base qw/ Exporter /;
our @EXPORT = qw/ ecb_encrypt
                  ecb_decrypt
                  cbc_decrypt
                  cbc_encrypt
                  ctr_stream
                  prng_stream /;

sub ecb_encrypt {
    my ($cipher, $plaintext) = @_;
    $plaintext = pad_pkcs7($plaintext, 16);
    my $ciphertext = '';
    for (my $offset = 0; $offset < length($plaintext); $offset += 16) {
        my $block = substr($plaintext, $offset, 16);
        $ciphertext .= $cipher->($block);
    }
    return $ciphertext;
}

sub ecb_decrypt {
    my ($cipher, $ciphertext) = @_;
    my $plaintext = '';
    for (my $offset = 0; $offset < length($ciphertext); $offset += 16) {
        my $block = substr($ciphertext, $offset, 16);
        $plaintext .= $cipher->($block);
    }
    $plaintext = unpad_pkcs7($plaintext);
    return $plaintext;
}

sub cbc_encrypt {
    my ($cipher, $iv, $plaintext) = @_;
    $plaintext = pad_pkcs7($plaintext, 16);
    my $ciphertext = '';
    my $state = $iv;
    for (my $offset = 0; $offset < length($plaintext); $offset += 16) {
        my $block = substr($plaintext, $offset, 16);
        $state = $cipher->(xor_buffers($block, $state));
        $ciphertext .= $state;
    }
    return $ciphertext;
}

sub cbc_decrypt {
    my ($cipher, $iv, $ciphertext) = @_;
    my $plaintext = '';
    my $state = $iv;
    for (my $offset = 0; $offset < length($ciphertext); $offset += 16) {
        my $block = substr($ciphertext, $offset, 16);
        $plaintext .= xor_buffers($cipher->($block), $state);
        $state = $block;
    }
    $plaintext = unpad_pkcs7($plaintext);
    return $plaintext;
}

sub ctr_stream {
    my ($cipher, $nonce, $input) = @_;
    my $output = '';
    my $counter = 0;
    for (my $offset = 0; $offset < length($input); $offset += 16) {
        my $block = substr($input, $offset, 16);
        my $keystream = $cipher->encrypt($nonce . pack('Q<', $counter));
        substr $keystream, length($block), (16 - length($block)), ''
             if length($block) != length($keystream);
        $output .= xor_buffers($block, $keystream);
        $counter++;
    }
    return $output;
}

sub prng_stream {
    my ($prng, $input) = @_;
    my $output = '';
    for (my $offset = 0; $offset < length($input); $offset += 4) {
        my $block = substr($input, $offset, 4);
        my $rand = $prng->rand;
        my @keystream = unpack('C4', pack('V', $rand));
        my $keystream = join '', map { chr($_) } @keystream;
        substr $keystream, length($block), (4 - length($block)), ''
             if length($block) != length($keystream);
        $output .= xor_buffers($block, $keystream);
    }
    return $output;
}

1;
