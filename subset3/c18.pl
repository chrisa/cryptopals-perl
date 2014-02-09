use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::Modes;
use MtsoCrypt::Random;
use MtsoCrypt::Util;
use Crypt::OpenSSL::AES;

my $ciphertext = decode_base64('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==');

my $key = 'YELLOW SUBMARINE';
my $aes = Crypt::OpenSSL::AES->new($key);
my $nonce = "\x00" x 8;

my $plaintext = ctr_stream($aes, $nonce, $ciphertext);
print "$plaintext\n";

$ciphertext = ctr_stream($aes, $nonce, $plaintext);
$plaintext = ctr_stream($aes, $nonce, $ciphertext);
print "$plaintext\n";
