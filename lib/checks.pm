use strict;
use warnings;
use utf8;

use LWP::UserAgent;
use Geo::IP;
use Cwd;

sub get_protocols {
  my ($el) = @_;
  my @enabled;
  my @disabled;
  my %translate = (
    sslv2 => 'SSLv2',
    sslv3 => 'SSLv3',
    tlsv1 => 'TLSv1',
    tlsv1_1 => 'TLSv1.1',
    tlsv1_2 => 'TLSv1.2',
  );
  foreach (qw/sslv2 sslv3 tlsv1 tlsv1_1 tlsv1_2/) {
    push @enabled,  $translate{$_} if (exists $el->{$_} && keys %{$el->{$_}->{'acceptedCipherSuites'}} != 0);
    push @disabled, $translate{$_} if (!exists $el->{$_} || keys %{$el->{$_}->{'acceptedCipherSuites'}} == 0);
  }

  return {
    disabled => \@disabled,
    enabled  => \@enabled,
  };
}
sub has_rc4 {
  my ($el) = @_;
  my @acceptedCipher = keys %{$el->{'acceptedCipherSuites'}};

  if (grep {$_ =~ /rc4/i} @acceptedCipher) {
    return {enabled => 1, reason => 'RC4 cipher détecté'};
  }

  return {enabled => 0};
}

sub has_des {
  my ($el) = @_;
  my @acceptedCipher = keys %{$el->{'acceptedCipherSuites'}};

  if (grep {$_ =~ /^des/i} @acceptedCipher) {
    return {enabled => 1, reason => 'DES cipher détecté'};
  }

  return {enabled => 0};
}

sub has_md5 {
  my ($el) = @_;
  my @acceptedCipher = keys %{$el->{'acceptedCipherSuites'}};

  if (grep {$_ =~ /md5/i} @acceptedCipher) {
    return {enabled => 1, reason => 'MD5 cipher détecté'};
  }

  return {enabled => 0};
}

sub has_null {
  my ($el) = @_;
  my @acceptedCipher = keys %{$el->{'acceptedCipherSuites'}};

  if (grep {$_ =~ /null/i} @acceptedCipher) {
    return (enabled => 1, reason => 'NULL cipher détecté');
  }

  return (enabled => 0);
}

sub get_cert_info {
  my ($el) = @_;
  my $cert_chain = $el->{'certinfo'}->{'certificateChain'}->{'certificate'};

  my $site_cert;
  eval {
    $site_cert = $cert_chain->[0];
    1;
  } or do {
    $site_cert = $cert_chain;
  };

  my $ocsp = 0;
  if (
    exists $el->{'certinfo'}->{'ocspStapling'}->{'responseStatus'} &&
    $site_cert->{'ocspStapling'}->{'responseStatus'} eq 'successful'
  ) {
    $ocsp = 1;
  }

  return {
    altNames           => $site_cert->{'extensions'}->{'X509v3SubjectAlternativeName'}->{'listEntry'},
    commonName         => $site_cert->{'subject'}->{'commonName'},
    issuer             => $site_cert->{'issuer'}->{'commonName'},
    keySize            => $site_cert->{'subjectPublicKeyInfo'}->{'publicKeySize'},
    notAfter           => $site_cert->{'validity'}->{'notAfter'},
    notBefore          => $site_cert->{'validity'}->{'notBefore'},
    ocspStapling       => $ocsp,
    publicKeyAlgorithm => $site_cert->{'subjectPublicKeyInfo'}->{'publicKeyAlgorithm'},
    signatureAlgorithm => $site_cert->{'signatureAlgorithm'},
  };
}

sub get_ciphers {
  my ($el) = @_;

  my @sslv2   = keys %{$el->{'sslv2'}->{'acceptedCipherSuites'}->{'cipherSuite'}};
  my @sslv3   = keys %{$el->{'sslv3'}->{'acceptedCipherSuites'}->{'cipherSuite'}};
  my @tlsv1   = keys %{$el->{'tlsv1'}->{'acceptedCipherSuites'}->{'cipherSuite'}};
  my @tlsv1_1 = keys %{$el->{'tlsv1_1'}->{'acceptedCipherSuites'}->{'cipherSuite'}};
  my @tlsv1_2 = keys %{$el->{'tlsv1_2'}->{'acceptedCipherSuites'}->{'cipherSuite'}};

  my (%ciphers, $tmp, @tmp);
  foreach my $proto (qw/sslv2 sslv3 tlsv1 tlsv1_1 tlsv1_2/) {
    eval {
      @tmp = keys %{$el->{$proto}->{'acceptedCipherSuites'}->{'cipherSuite'}};
      foreach my $cipher (@tmp) {
        $tmp = $el->{$proto}->{'acceptedCipherSuites'}->{'cipherSuite'}->{$cipher};
        if (!$ciphers{$cipher}) {
          $ciphers{$cipher} = {
            keySize => $tmp->{'keySize'},
            type    => $tmp->{'keyExchange'}->{'Type'},
          };
        }
      }
      1;
    } or do {
      $tmp = $el->{$proto}->{'acceptedCipherSuites'}->{'cipherSuite'};
      if (!$ciphers{$tmp->{'name'}}) {
        $ciphers{$tmp->{'name'}} = {
          keySize => $tmp->{'keySize'},
          type    => 'none',
        };
        if (exists $tmp->{'keyExchange'}) {
          $ciphers{$tmp->{'name'}}{'type'} = $tmp->{'keyExchange'}->{'Type'};
        }
      }
    };
  }
  return \%ciphers;  
}

sub get_preferred {
  my ($el) = @_;

  my $sslv2   = $el->{'sslv2'}->{'preferredCipherSuite'}->{'cipherSuite'};
  my $sslv3   = $el->{'sslv3'}->{'preferredCipherSuite'}->{'cipherSuite'};
  my $tlsv1   = $el->{'tlsv1'}->{'preferredCipherSuite'}->{'cipherSuite'};
  my $tlsv1_1 = $el->{'tlsv1_1'}->{'preferredCipherSuite'}->{'cipherSuite'};
  my $tlsv1_2 = $el->{'tlsv1_2'}->{'preferredCipherSuite'}->{'cipherSuite'};

  return {
    sslv2   => {name => $sslv2->{'name'},  keySize => $sslv2->{'keySize'}, type => $sslv2->{'keyExchange'}{'Type'}},
    sslv3   => {name => $sslv3->{'name'},  keySize => $sslv3->{'keySize'}, type => $sslv3->{'keyExchange'}{'Type'}},
    tlsv1   => {name => $tlsv1->{'name'},  keySize => $tlsv1->{'keySize'}, type => $tlsv1->{'keyExchange'}{'Type'}},
    tlsv1_1 => {name => $tlsv1_1->{'name'}, keySize => $tlsv1_1->{'keySize'}, type => $tlsv1_1->{'keyExchange'}{'Type'}},
    tlsv1_2 => {name => $tlsv1_2->{'name'}, keySize => $tlsv1_2->{'keySize'}, type => $tlsv1_2->{'keyExchange'}{'Type'}},
  };
}

sub get_page_info {
  my ($host) = @_;
  my @useragents = (
    'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0',
    'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0',
    'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0',
    'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)',
  );

  my $agent = $useragents[rand @useragents];
  my $ua = LWP::UserAgent->new();
  $ua->timeout(5);
  $ua->agent($agent);

  my $force_ssl;

  my $req = HTTP::Request->new('GET',"http://${host}/");
  my $res = $ua->request($req);
  my @redirects = $res->redirects;
  if ($res->code != 200) {
    $force_ssl = 2;
  } else {
    if ($#redirects > 0) {
      my @last_redir = $redirects[-2];
      my @headers = $last_redir[0]->headers;
      if ($headers[0]{'location'} =~ /^https:/i) {
        $force_ssl = 1;
      } else {
        $force_ssl = 0;
      }
    } else {
      $force_ssl = 0;
    }
  }
  my $content = $res->content;

  # check if there is some shockwave/flash
  my $has_flash = ($content =~ /\<object/i);

  # check if there are frames
  my $has_frame = ($content =~ /<i?frame/i);
  my $x_frame_option = '';
  if ($has_frame && $res->headers->{'x-frame-options'}) {
    $x_frame_option = $res->headers->{'x-frame-options'};
  }

  # check HSTS
  my $hsts = '';
  if ($res->headers->{'strict-transport-security'}) {
    $hsts = $res->headers->{'strict-transport-security'};
  }

  return {
    flash     => $has_flash      || 0,
    frame     => $has_frame      || 0,
    force_ssl => $force_ssl      || 0,
    hsts      => $hsts,
    xframeopt => $x_frame_option,
  };
}

sub get_country {
  my ($ip) = @_;
  my $p = cwd();
  my $gi = Geo::IP->open("${p}/external/GeoIP.dat", GEOIP_STANDARD);
  my $record = $gi->country_code_by_addr($ip);
  return {
    code => $record,
    ip   => $ip,
  };
}


1;
