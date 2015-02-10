package checks;

use strict;
use warnings;

require Exporter;
our @ISA = qw(Exporter);


our @EXPORT_OK = qw/has_sslv2 has_sslv3 has_rc4 has_des/;


sub has_sslv2 {
  my ($el) = @_;
  my $k = keys %{$el->{'sslv2'}->{'acceptedCipherSuites'}};
  
  return ($k > 0);
}

sub has_sslv3 {
  my ($el) = @_;
  my $k = keys %{$el->{'sslv3'}->{'acceptedCipherSuites'}};
  
  return ($k > 0);
}

sub has_rc4 {
  my ($el) = @_;
}

sub has_des {
  my ($el) = @_;
}

1;
