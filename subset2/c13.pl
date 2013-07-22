use strict;
use warnings;
use MtsoCrypt::Encoding;
use MtsoCrypt::Modes;
use MtsoCrypt::Random;
use MtsoCrypt::Metrics;
use Data::Dumper;
use Crypt::OpenSSL::AES;

# we'll choose to register an regular user account 'admin@bar.com'.
my $cookie = profile_for('admin@bar.com');
print Dumper read_profile($cookie);

# now we'll make a new user with an email address containing 'admin',
# with a prefix to place it at the start of the second ciphertext
# block, plus pkcs7 padding for the end of the plaintext.
my $admin_cookie = profile_for(('x' x 10) . 'admin' . (chr(11) x 11));

# borrow second block of ciphertext from this second cookie
my $block = substr $admin_cookie, 16, 16;

# splice it into the original cookie as the third block
substr $cookie, 32, 16, $block;

# and?
print Dumper read_profile($cookie);

# critical point here - we get to choose the email address, so choose
# it to place the role name in a ciphertext block on its own, without
# metacharacters '&' and '=':
#
# email=admin@bar.com&uid=10&role=user
# aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbcccccccccccccccc
#
# here we only need to overwrite block c, with just the string "admin".

# --------------------------------------------------------------------
# profile-creating oracle function

sub profile_for {
    my ($email) = @_;
    my $data = {
        email => $email,
        role => 'user',
        uid => 10,
    };

    # specifying order of keys to ensure it's stable
    # (without ordered-hash hacks)
    return encrypt_cookie(write_cookie($data, [qw/ email uid role /]));
}

sub read_profile {
    my ($cookie) = @_;
    my $encoded = decrypt_cookie($cookie);
    return parse_cookie($encoded);
}

# --------------------------------------------------------------------
# encrypt/decrypt wrappers

my $key;

sub encrypt_cookie {
    my ($cookie) = @_;
    $key ||= random_key();
    my $aes = Crypt::OpenSSL::AES->new($key);
    return ecb_encrypt(sub { $aes->encrypt($_[0]) }, $cookie);
}

sub decrypt_cookie {
    my ($cookie) = @_;
    $key ||= random_key();
    my $aes = Crypt::OpenSSL::AES->new($key);
    return ecb_decrypt(sub { $aes->decrypt($_[0]) }, $cookie);
}
