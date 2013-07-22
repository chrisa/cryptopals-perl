package MtsoCrypt::Encoding;
use strict;
use warnings;
use MIME::Base64 ();
use Carp qw/ croak /;
use base qw/ Exporter /;
our @EXPORT = qw/ encode_hex
                  encode_base64
                  decode_hex
                  decode_base64
                  pad_pkcs7
                  unpad_pkcs7
                  parse_cookie
                  write_cookie /;

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

sub pad_pkcs7 {
    my ($data, $blocklen) = @_;
    my $mod = $blocklen - (length($data) % $blocklen);
    return $data . (chr($mod) x $mod);
}

sub unpad_pkcs7 {
    my ($data) = @_;
    my $count = ord(substr($data, -1, 1));
    for (1..$count) {
        unless (ord(chop $data) eq $count) {
            croak "invalid PKCS#7 padding";
        }
    }
    return $data;
}

sub parse_cookie {
    my ($cookie) = @_;
    my @kvs = split /&/, $cookie;
    my %kvs = map { split /=/ } @kvs;
    return \%kvs;
}

sub write_cookie {
    my ($kvs, $keys) = @_;
    my @cookie;
    for my $k (@$keys) {
        my $key = $k;
        $key =~ s/[&=]//g;
        my $value = $kvs->{$k};
        $value =~ s/[&=]//g;
        push @cookie, "$key=$value";
    }
    return join '&', @cookie;
}

1;
