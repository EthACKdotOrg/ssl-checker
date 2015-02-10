use strict;
use warnings;

sub has_sslv2 {
  my ($el) = @_;
  my $k = keys %{$el->{'sslv2'}->{'acceptedCipherSuites'}};
  
  return ($k > 0) || 0;
}

sub has_sslv3 {
  my ($el) = @_;
  my $k = keys %{$el->{'sslv3'}->{'acceptedCipherSuites'}};
  
  return ($k > 0) || 0;
}

sub has_rc4 {
  my ($el) = @_;
  my @acceptedCipher = keys %{$el->{'acceptedCipherSuites'}};

  return (grep {$_ =~ /rc4/i} @acceptedCipher);
}

sub has_des {
  my ($el) = @_;
  my @acceptedCipher = keys %{$el->{'acceptedCipherSuites'}};

  return (grep {$_ =~ /^des/i} @acceptedCipher);
}

sub has_md5 {
  my ($el) = @_;
  my @acceptedCipher = keys %{$el->{'acceptedCipherSuites'}};

  return (grep {$_ =~ /md5/i} @acceptedCipher);
}

sub has_null {
  my ($el) = @_;
  my @acceptedCipher = keys %{$el->{'acceptedCipherSuites'}};

  return (grep {$_ =~ /null/i} @acceptedCipher);
}

1;
