package ssl::heartbleed;

# Mostly inspired by
# https://github.com/noxxi/p5-scripts/blob/master/check-ssl-heartbleed.pl

use strict;
use warnings;

require Exporter;
our @ISA = qw(Exporter);

our @EXPORT_OK = qw/check_heartbleed/;


use IO::Socket::IP;

sub check_heartbleed {
  my ($host, $ssl_version) = @_;

  # these are the ciphers we try
  # that's all openssl -V ciphers reports with my openssl1.0.1
  my @ssl3_ciphers = (
    0xC0,0x14, 0xC0,0x0A, 0xC0,0x22, 0xC0,0x21, 0x00,0x39, 0x00,0x38,
    0x00,0x88, 0x00,0x87, 0xC0,0x0F, 0xC0,0x05, 0x00,0x35, 0x00,0x84,
    0x00,0x8D, 0xC0,0x12, 0xC0,0x08, 0xC0,0x1C, 0xC0,0x1B, 0x00,0x16,
    0x00,0x13, 0xC0,0x0D, 0xC0,0x03, 0x00,0x0A, 0x00,0x8B, 0xC0,0x13,
    0xC0,0x09, 0xC0,0x1F, 0xC0,0x1E, 0x00,0x33, 0x00,0x32, 0x00,0x9A,
    0x00,0x99, 0x00,0x45, 0x00,0x44, 0xC0,0x0E, 0xC0,0x04, 0x00,0x2F,
    0x00,0x96, 0x00,0x41, 0x00,0x8C, 0xC0,0x11, 0xC0,0x07, 0xC0,0x0C,
    0xC0,0x02, 0x00,0x05, 0x00,0x04, 0x00,0x8A, 0x00,0x15, 0x00,0x12,
    0x00,0x09, 0x00,0x14, 0x00,0x11, 0x00,0x08, 0x00,0x06, 0x00,0x03,
  );
  my @tls12_ciphers = (
    0xC0,0x30, 0xC0,0x2C, 0xC0,0x28, 0xC0,0x24, 0x00,0xA3, 0x00,0x9F,
    0x00,0x6B, 0x00,0x6A, 0xC0,0x32, 0xC0,0x2E, 0xC0,0x2A, 0xC0,0x26,
    0x00,0x9D, 0x00,0x3D, 0xC0,0x2F, 0xC0,0x2B, 0xC0,0x27, 0xC0,0x23,
    0x00,0xA2, 0x00,0x9E, 0x00,0x67, 0x00,0x40, 0xC0,0x31, 0xC0,0x2D,
    0xC0,0x29, 0xC0,0x25, 0x00,0x9C, 0x00,0x3C,
  );

  my $ssls = {
    'sslv3'  => 0x300,
    'tlsv1'  => 0x301,
    'tlsv11' => 0x302,
    'tlsv12' => 0x303,
  };


  my @ciphers = (( $ssl_version eq 'tls12' ? @tls12_ciphers : ()), @ssl3_ciphers );
  my ($cl,$use_version) = _connect( $host, $ssls->{$ssl_version}, \@ciphers );

  if ($use_version) {
    my $hb = pack("Cnn/a*",0x18,$use_version,
      pack("Cn",1,0x4000));

    for (1..2) {
      print $cl substr($hb,0,1);
      print $cl substr($hb,1);
    }

    my $err;
    if ( my ($type,$ver,$buf) = _readframe($cl,\$err,1)) {
      if ( $type == 21 ) {
        return (1, 'probably NOT vulnerablei (1)');
      } elsif ( $type != 24 ) {
        return (99, 'unknown, unexpected answer');
      } elsif ( length($buf)>3 ) {
        return (2, 'vulnerable');
      } else {
        return (0, 'NOT vulnerable');
      }
    } else {
      return (1, 'probably NOT vulnerable (2)');
    }
  } else {
    return (99, 'unknown, unexpected hello answer');
  }

}



sub _connect {
  my ($host, $ssl_version, $ciphers) = @_;

  my $cl = IO::Socket::IP->new(
    PeerHost => $host,
    PeerPort => "https",
  ) or die "Unable to connect $!\n";

  # disable NAGLE to send heartbeat with multiple small packets
  setsockopt($cl,6,1,pack("l",1));

  my $ext = '';
  $ext .= pack('nn/a*', 0x00,   # server_name extension + length
    pack('n/a*',              # server_name list length
      pack('Cn/a*',0,$host)  # type host_name(0) + length/server_name
    ));


  # built and send ssl client hello
  my $hello_data = pack("nNn14Cn/a*C/a*n/a*",
    $ssl_version,
    time(),
    ( map { rand(0x10000) } (1..14)),
    0, # session-id length
    pack("C*",@$ciphers),
    "\0", # compression null
    $ext,
  );

  $hello_data = substr(pack("N/a*",$hello_data),1); # 3byte length
  print $cl pack(
    "Cnn/a*",0x16,$ssl_version,  # type handshake, version, length
    pack("Ca*",1,$hello_data),   # type client hello, data
  );

  my $use_version;
  my $got_server_hello;
  my $err;
  while (1) {
    my ($type,$ver,@msg) = _readframe($cl,\$err) or return;

    # first message must be server hello
    $got_server_hello ||= $type == 22 and grep { $_->[0] == 2 } @msg;
    return if ! $got_server_hello;

    # wait for server hello done
    if ( $type == 22 and grep { $_->[0] == 0x0e } @msg ) {
      # server hello done
      $use_version = $ver;
      last;
    }
  }

  return ($cl,$use_version);
}

sub _readframe {
  my ($cl,$rerr,$errok) = @_;
  my $len = 5;
  my $buf = '';
  vec( my $rin = '',fileno($cl),1 ) = 1;
  while ( length($buf)<$len ) {
    if ( ! select( my $rout = $rin,undef,undef,5 )) {
      $$rerr = 'timeout';
      last if $errok;
      return;
    };
    if ( ! sysread($cl,$buf,$len-length($buf),length($buf))) {
      $$rerr = "eof";
      $$rerr .= " after ".length($buf)." bytes" if $buf ne '';
      last if $errok;
      return;
    }
    $len = unpack("x3n",$buf) + 5 if length($buf) == 5;
  }
  return if length($buf)<5;
  (my $type, my $ver) = unpack("Cnn",substr($buf,0,5,''));
  my @msg;
  if ( $type == 22 ) {
    while ( length($buf)>=4 ) {
      my ($ht,$len) = unpack("Ca3",substr($buf,0,4,''));
      $len = unpack("N","\0$len");
      push @msg,[ $ht,substr($buf,0,$len,'') ];
    }
  } else {
    @msg = $buf;
  }

  return ($type,$ver,@msg);
}
