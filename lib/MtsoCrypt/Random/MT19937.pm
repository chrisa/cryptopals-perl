package MtsoCrypt::Random::MT19937;
use strict;
use warnings;

# Mersenne Twister implementation

sub new {
    my ($class) = @_;
    my $self = bless {}, $class;
    $self->{MT} = [];
    $self->{index} = 0;
    return $self;
}

sub srand {
    my ($self, $seed) = @_;
    $self->{index} = 0;
    $self->{MT} = [$seed];
    for (my $i = 1; $i <= 623; $i++) {
        $self->{MT}->[$i] = 0xffffffff & (1812433253 * ($self->{MT}->[$i - 1] ^ ($self->{MT}->[$i - 1] >> 30)) + $i);
    }
}

sub rand {
    my ($self) = @_;
    if ($self->{index} == 0) {
        $self->_generate();
    }

    my $y = $self->{MT}->[$self->{index}];

    $y = $y ^ ($y >> 11);
    $y = $y ^ (($y << 7) & 2636928640);
    $y = $y ^ (($y << 15) & 4022730752);
    $y = $y ^ ($y >> 18);

    $self->{index} = ($self->{index} + 1) % 624;
    return $y;
}

sub _generate {
    my ($self) = @_;
    for (my $i = 1; $i <= 623; $i++) {
        my $y = ($self->{MT}->[$i] & 0x80000000) + ($self->{MT}->[($i + 1) % 624] & 0x7fffffff);
        $self->{MT}->[$i] = $self->{MT}->[($i + 397) % 624] ^ ($y >> 1);
        if (($y % 2) != 0) {
            $self->{MT}->[$i] = $self->{MT}->[$i] ^ 2567483615;
        }
    }
}

1;
