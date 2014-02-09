use strict;
use warnings;
use MtsoCrypt::Mac;
use MtsoCrypt::Hash;
use MtsoCrypt::Random;
use MtsoCrypt::Encoding;

my $key = random_key();
my $message = 'this is some message or other';

my $mac = keyed_mac(\&my_sha1, $key, $message);

printf STDERR "auth result: %d\n",
     auth_keyed_mac(\&my_sha1, $key, $message, $mac);

printf STDERR "auth result, modified message: %d\n",
     auth_keyed_mac(\&my_sha1, $key, $message . 'foo', $mac);
