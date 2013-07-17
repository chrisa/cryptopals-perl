package MtsoCrypt::Encoding;
use strict;
use warnings;
use MIME::Base64 ();
use base qw/ Exporter /;
our @EXPORT = qw/ encode_hex
                  encode_base64
                  decode_hex
                  decode_base64 /;

sub encode_hex {
    my ($buf) = @_;
    return unpack 'H*', $buf;
}

sub encode_base64 {
    my ($buf) = @_;
    return MIME::Base64::encode_base64($buf, '');
}

sub decode_hex {
    my ($hex) = @_;
    return pack 'H*', $hex;
}

sub decode_base64 {
    my ($base64) = @_;
    return MIME::Base64::decode_base64($base64);
}

1;
