use strict;
use warnings;
use utf8;

use LWP::UserAgent;

sub has_sslv2 {
  my ($el) = @_;
  my $k = keys %{$el->{'sslv2'}->{'acceptedCipherSuites'}};

  if ($k > 0) {
    return (enabled => 1, reason => 'SSLv2 activé');
  }
  
  return (enabled => 0);
}

sub has_sslv3 {
  my ($el) = @_;
  my $k = keys %{$el->{'sslv3'}->{'acceptedCipherSuites'}};
  
  if ($k > 0) {
    return {enabled => 1, reason => 'SSLv3 activé'};
  }
  
  return {enabled => 0};
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

  return {
    signatureAlgorithm => $site_cert->{'signatureAlgorithm'},
    issuer             => $site_cert->{'issuer'}->{'commonName'},
    notAfter           => $site_cert->{'validity'}->{'notAfter'},
    notBefore          => $site_cert->{'validity'}->{'notBefore'},
    keySize            => $site_cert->{'subjectPublicKeyInfo'}->{'publicKeySize'},
    publicKeyAlgorithm => $site_cert->{'subjectPublicKeyInfo'}->{'publicKeyAlgorithm'},
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
  my $content = $res->content;

  # check if there is some shockwave/flash
  my $has_flash = ($content =~ /<object/i);

  # check if there are frames
  my $has_frame = ($content =~ /<i?frame/i);
  my $x_frame_option = 0;
  if ($has_frame && $res->headers->{'x-frame-options'}) {
    $x_frame_option = $res->headers->{'x-frame-options'};
  }

  # check HSTS
  my $hsts = 0;
  if ($res->headers->{'strict-transport-security'}) {
    $hsts = $res->headers->{'strict-transport-security'};
  }

  return {
    flash     => $has_flash      || 0,
    frame     => $has_frame      || 0,
    force_ssl => $force_ssl      || 0,
    hsts      => $hsts           || 0,
    xframeopt => $x_frame_option || '',
  };
}


1;
