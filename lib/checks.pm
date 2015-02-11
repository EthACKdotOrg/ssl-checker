use strict;
use warnings;
use utf8;

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

  my @merged = (@sslv2, @sslv3, @tlsv1, @tlsv1_1, @tlsv1_2);
  my @ciphers;
  foreach my $cipher (@merged) {
    push @ciphers, $cipher if (!grep {$_ eq $cipher} @ciphers);
  }

  return \@ciphers;  
}

sub get_preferred {
  my ($el) = @_;

  my $sslv2   = $el->{'sslv2'}->{'preferredCipherSuite'}->{'cipherSuite'}->{'name'};
  my $sslv3   = $el->{'sslv3'}->{'preferredCipherSuite'}->{'cipherSuite'}->{'name'};
  my $tlsv1   = $el->{'tlsv1'}->{'preferredCipherSuite'}->{'cipherSuite'}->{'name'};
  my $tlsv1_1 = $el->{'tlsv1_1'}->{'preferredCipherSuite'}->{'cipherSuite'}->{'name'};
  my $tlsv1_2 = $el->{'tlsv1_2'}->{'preferredCipherSuite'}->{'cipherSuite'}->{'name'};

  return {
    sslv2   => $sslv2,
    sslv3   => $sslv3,
    tlsv1   => $tlsv1,
    tlsv1_1 => $tlsv1_1,
    tlsv1_2 => $tlsv1_2,
  };
}

1;
