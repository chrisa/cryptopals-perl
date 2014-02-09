use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::Modes;
use MtsoCrypt::Random;
use Crypt::OpenSSL::AES;

my $ciphertext = encrypt(';admin=true');
print "\nfound ;admin=true; trivially :(\n" if decrypt($ciphertext);

# : is one LSB flip from ;
# < is one LSB flip from =

$ciphertext = encrypt(':admin<true');
my $block3 = substr $ciphertext, 32, 16;

flip_bit(\$block3, 0, 0);
flip_bit(\$block3, 6, 0);

substr $ciphertext, 32, 16, $block3;
print "found ;admin=true;\n" if decrypt($ciphertext);

# --------------------------------------------------------------------
# utility function to flip $bit of $byte in the scalar-ref $textref

sub flip_bit {
    my ($textref, $byte, $bit) = @_;
    vec(substr($$textref, $byte, 1), $bit, 1) ^= 1;
}

# --------------------------------------------------------------------
# encrypt / decrypt functions under attack

my ($key, $nonce);

sub encrypt {
    my ($input) = @_;
    $key ||= random_key();
    $nonce ||= "\0" x 8;
    my $aes = Crypt::OpenSSL::AES->new($key);

    my $prefix = 'comment1=cooking%20MCs;userdata=';
    my $suffix = ';comment2=%20like%20a%20pound%20of%20bacon';

    # hex-escape our metacharacters to match the escaping already
    # present in the prefix and suffix.

    $input =~ s/([;=])/sprintf('%%%x', ord($1))/ge;

    my $plaintext = $prefix . $input . $suffix;
    return ctr_stream($aes, $nonce, $plaintext);
}

sub decrypt {
    my ($ciphertext) = @_;
    $key ||= random_key();
    $nonce ||= "\0" x 8;
    my $aes = Crypt::OpenSSL::AES->new($key);

    my $plaintext = ctr_stream($aes, $nonce, $ciphertext);
    print "$plaintext\n";
    return $plaintext =~ /;admin=true;/ ? 1 : 0;
}
