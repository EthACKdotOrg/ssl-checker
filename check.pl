#!/usr/bin/env perl

use warnings;
use strict;
use Text::CSV;
use Perl::Version;
use POSIX qw/strftime/;
use Time::ParseDate;
use Getopt::Long;
use File::Spec;
use File::Temp qw/tempfile/;
use Term::ANSIColor qw(:constants);
use JSON;
use Digest::SHA;
use XML::XML2JSON;
use XML::Simple;
use IO::Socket::SSL;
use Time::ParseDate;

use lib 'lib';
use checks;
use trackers;


my $help = '';
my $url_file = './urls';
my $output_dir = './';
my $refresh = '';

GetOptions (
  'help|h'     => \$help,
  'output|o=s' => \$output_dir,
  'refresh|r'  => \$refresh,
  'urls|u=s'   => \$url_file,
);

if (! -d $output_dir) {
  die "Please create ${output_dir} first!";
}

if (! -x $output_dir) {
  die "Apparently unable to write in ${output_dir}";
}
if (! -f $url_file) {
  die "Apparently unable to read ${url_file}";
}
if (! -r $url_file) {
  die "Apparently unable to read ${url_file}";
}


my $csv = Text::CSV->new();

my $json_obj = JSON->new;
$json_obj->utf8(1);
my $json = {};
my $json_version = Perl::Version->new('2.1.0');
my $date = strftime "%Y-%m-%d", localtime;

my $json_output = File::Spec->catfile($output_dir, "${date}.json");

if (-f $json_output && !$refresh) {
  local $/;
  open FH, '<', $json_output or die $!;
  my $js = <FH>;
  $json = $json_obj->decode($js);
  close FH;
}

if (!exists $json->{'version'} or $json_version > Perl::Version->new($json->{'version'})) {
  $json = {};
}


$json->{'version'} = $json_version->stringify();
$json->{'date'} = $date;

open my $fh,  '<:encoding(utf8)', $url_file or die $!;
my ($front, $ebanking, $bank_name, $result);
while(my $row = $csv->getline($fh)) {
  $bank_name = trim($row->[0]);
  $front = trim($row->[1]);

  if ($bank_name !~ /^#/) {

    if (!exists $json->{$bank_name} || $refresh) {
      $json->{'banks'}->{$bank_name}->{'frontend'} = $front;

      if (scalar @{$row} == 3) {
        $ebanking = trim($row->[2]);
        if ($front ne $ebanking) {
          $result = sslyze($refresh, $bank_name, $front, $ebanking);
          $json->{'banks'}->{$bank_name}->{'backend'} = $ebanking;
        } else {
          $result = sslyze($refresh, $bank_name, $front);
          $json->{'banks'}->{$bank_name}->{'backend'} = 'self';
        }
      } else {
        $result = sslyze($refresh, $bank_name, $front);
        $json->{'banks'}->{$bank_name}->{'backend'} = 'app';
      }
      $json->{'banks'}->{$bank_name}->{'results'} = $result;
    }
  }
}
close $url_file;

open FH, '>', $json_output or die $!;
print FH $json_obj->pretty->encode($json);
close FH;

# create/update json index
my $index = File::Spec->catfile($output_dir, 'index.json');
my $index_json = [];
if (-e $index) {
  local $/;
  open FH, '<', $index or die $!;
  my $js = <FH>;
  $index_json = $json_obj->decode($js);
  close FH;
}

push @$index_json, $date if (!grep {$_ eq $date} @$index_json);
open FH, '>', $index or die $!;
print FH $json_obj->pretty->encode($index_json);
close FH;

# call sslyze in a way we can use its threading capabilities
# well, not fully though, but… better than nothing.
sub sslyze {
  my ($refresh, $name, $frontend, $backend) = @_;


  my $ctx = Digest::SHA->new('sha256');
  $ctx->add($name);
  my $digest = $ctx->hexdigest;

  my $json_out = File::Spec->catfile('xmls', "${digest}.json");

  my ($backend_check, $frontend_check) = 0;

  my $local_json = {};

  if (!-e $json_out || $refresh) {
    my $json_obj = JSON->new;
    $json_obj->utf8(1);

    my ($fh, $out_tmp) = tempfile();

    my $sock = IO::Socket::SSL->new(
      PeerHost        => $frontend,
      PeerPort        => 'https',
      SSL_verify_mode => SSL_VERIFY_NONE,
      SSL_ca_path     => '/etc/ssl/certs',
      Timeout         => 3,
    );

    my @cmd = (
      './external/sslyze/sslyze.py', 
      '--regular',
      '--xml_out',
      $out_tmp,
    );
    
    if ($sock && $sock->opened) {
      print $sock "GET / HTTP/1.0\r\n\r\n";
      $sock->close(SSL_ctx_free => 1);
      push @cmd,'--sni', $frontend, $frontend;
      $frontend_check = 1;
    }
    my $xml = new XML::Simple;
    if ($frontend_check) {
      system(@cmd);
      my $tmpdata = $xml->XMLin($out_tmp);
      my $xml2js = XML::XML2JSON->new(
        debug  => 0,
        pretty => 0,
      );
      my $tmp_json = $json_obj->decode($xml2js->obj2json($tmpdata));
      push @{$local_json->{'results'}}, $tmp_json->{'results'}->{'target'};
    }

    if ($backend) {
      ($fh, $out_tmp) = tempfile();
      @cmd = (
        './external/sslyze/sslyze.py', 
        '--regular',
        '--xml_out',
        $out_tmp,
      );

      $sock = IO::Socket::SSL->new(
        PeerHost        => $backend,
        PeerPort        => 'https',
        SSL_verify_mode => SSL_VERIFY_NONE,
        SSL_ca_path     => '/etc/ssl/certs',
        Timeout         => 3,
      );
      if ($sock && $sock->opened) {
        print $sock "GET / HTTP/1.0\r\n\r\n";
        $sock->close(SSL_ctx_free => 1);
        push @cmd, '--sni', $backend, $backend;
        $backend_check = 1;
      }
      if ($backend_check) {
        system(@cmd);
        my $tmpdata = $xml->XMLin($out_tmp);
        my $xml2js = XML::XML2JSON->new(
          debug  => 0,
          pretty => 0,
        );
        my $tmp_json = $json_obj->decode($xml2js->obj2json($tmpdata));
        push @{$local_json->{'results'}}, $tmp_json->{'results'}->{'target'};
      }
      
    }
    if (keys %{$local_json}) {
      open my $fh, '>:encoding(utf-8)', $json_out or die $!;
      print $fh $json_obj->pretty->encode($local_json);
      close $fh;
    }
  }

  if ($frontend_check || $backend_check) {
    return compute($local_json);
  } elsif (-e $json_out) {
    local $/;
    open FH, '<', $json_out or die $!;
    my $local_json = <FH>;
    close FH;
    $local_json = $json_obj->decode($local_json);
    return compute($local_json);
  } else {
    print "${name}: no data\n";
    return {};
  }
}


# do some computations based on the results we got from sslyze
# also, fetch some other information in order to find more stuff
sub compute {
  my ($json) = @_;

  my %output;
  my @array;
  #
  # multiple target?
  eval {
    @array = @{$json->{'results'}} ;
    1;
  } or do {
    push @array,  $json->{'results'};
  };

  foreach my $el (@array) {
    $output{$el->{'host'}}{'country'}     = get_country($el->{'ip'});
    $output{$el->{'host'}}{'response' }   = get_page_info($el->{'host'});
    $output{$el->{'host'}}{'trackers'}   = find_trackers($el->{'host'});
    $output{$el->{'host'}}{'protocols'}   = get_protocols($el);
    $output{$el->{'host'}}{'rc4'}         = has_rc4($el);
    $output{$el->{'host'}}{'des'}         = has_des($el);
    $output{$el->{'host'}}{'md5'}         = has_md5($el);
    $output{$el->{'host'}}{'null'}        = has_null($el);
    $output{$el->{'host'}}{'key'}         = get_cert_info($el);
    $output{$el->{'host'}}{'compression'} = $el->{'compression'}->{'compressionMethod'}->{'isSupported'};
    $output{$el->{'host'}}{'ciphers'}     = get_ciphers($el);
    $output{$el->{'host'}}{'preferredCiphers'}  = get_preferred($el);
  }

  # do some maths
  my ($grade, $max_grade);
  while(my ($host, $values) = each(%output)) {
    my $grade = 0;
    my $max_grade = 0;

    # Tracking users?
    $values->{'grades'}->{'trackers'} = 0;
    if (scalar @{$values->{'trackers'}} == 0) {
      $grade += 0.5;
      $values->{'grades'}->{'trackers'} = 0.5;
    }
    $max_grade += 0.5;

    # preferred cipher: DH?
    $values->{'grades'}->{'ciphers'}  = 0;
    while(my ($proto, $d) = each(%{$values->{'preferredCiphers'}})) {
      if ($d->{'type'} && $d->{'type'} =~ /^(EC)?DH$/) {
        $grade += 0.5;
        $values->{'grades'}->{'ciphers'}  += 0.5;
        if ($d->{'type'} =~ /^DH$/ && $d->{'ksize'} >= 1024) {
          $values->{'grades'}->{'ciphers'}  += 0.5;
          $grade += 0.5;
        }
        if ($d->{'type'} =~ /^ECDH$/ && $d->{'ksize'} >= 256) {
          $values->{'grades'}->{'ciphers'}  += 0.5;
          $grade += 0.5;
        }
      }
    }
    $max_grade += 3; # only TLS* have cool ciphers

    # protocols
    $values->{'grades'}->{'protocols'} = 0;
    $values->{'grades'}->{'protocols'} += 0.5 if (grep {$_ eq 'TLSv1'} @{$values->{'protocols'}->{'enabled'}});
    $values->{'grades'}->{'protocols'} += 0.5 if (grep {$_ eq 'TLSv1.1'} @{$values->{'protocols'}->{'enabled'}});
    $values->{'grades'}->{'protocols'} += 0.5 if (grep {$_ eq 'TLSv1.2'} @{$values->{'protocols'}->{'enabled'}});

    $values->{'grades'}->{'protocols'} -= 0.5 if (grep {$_ eq 'SSLv2'} @{$values->{'protocols'}->{'enabled'}});
    $values->{'grades'}->{'protocols'} -= 0.5 if (grep {$_ eq 'SSLv3'} @{$values->{'protocols'}->{'enabled'}});

    $grade += $values->{'grades'}->{'protocols'};
    $max_grade += 1.5;

    $max_grade += 1;

    # signature: SHA2?
    $values->{'grades'}->{'signature'} = 0;
    if ($values->{'key'}->{'signatureAlgorithm'} =~ /^sha2/i) {
      $grade += 0.5;
      $values->{'grades'}->{'signature'} = 0.5;
    }
    $max_grade += 0.5;

    # certificate still valid?
    $values->{'grades'}->{'cert_validity'} = 0;
    my $end_certificate = parsedate($values->{'key'}->{'notAfter'});
    my $start_certificate = parsedate($values->{'key'}->{'notBefore'});
    if ($end_certificate > time() && $start_certificate < time()) {
      $values->{'grades'}->{'cert_validity'} = 1;
      $grade += 1;
    }
    $max_grade += 1;

    # certificate valid for used domain?
    $values->{'grades'}->{'cert_match'} = 0;
    if ($values->{'key'}->{'hostnameValidation'}->{'certificateMatchesServerHostname'}) {
      $grade += 1;
      $values->{'grades'}->{'cert_match'} = 1;
    }
    $max_grade += 1;

    # key: 2048? more ?? :)
    my @size = split ' ', $values->{'key'}->{'keySize'};
    if ($size[0] < 1024) {
      $grade -= 1;
      $values->{'grades'}->{'keysize'} = -1;
    } elsif ($size[0] < 2048) {
      $grade -= 0.5;
      $values->{'grades'}->{'keysize'} = -0.5;
    } elsif ($size[0] < 4096) {
      $grade += 0.5;
      $values->{'grades'}->{'keysize'} = 0.5;
    }
    $max_grade += 0.5;

    # HSTS ?
    $values->{'grades'}->{'hsts'} = 0;
    if ($values->{'response'}->{'hsts'} ne '') {
      $values->{'grades'}->{'hsts'} = 1;
      $grade += 1;
    }
    $max_grade += 1;

    # enforce SSL?
    $values->{'grades'}->{'enforce_ssl'} = 0;
    if ($values->{'response'}->{'force_ssl'} > 0) {
      $values->{'grades'}->{'enforce_ssl'} = 0.5;
      $grade += 0.5;
    }
    $max_grade += 0.5;

    # OCSP Stapling?
    $values->{'grades'}->{'ocsp_stapling'} = 0;
    if ($values->{'key'}{'ocspStapling'} != 0) {
      $values->{'grades'}->{'ocsp_stapling'} = 0.5;
      $grade += 0.5;
    }
    $max_grade += 0.5;

    # Flash?
    $values->{'grades'}->{'flash'} = 0;
    if ($values->{'response'}{'flash'} == 0) {
      $values->{'grades'}->{'flash'} = 0.5;
      $grade += 0.5;
    }
    $max_grade += 0.5;

    # Protected frame?
    $values->{'grades'}->{'frames'} = 0;
    if (
      $values->{'response'}{'frame'} == 0 ||
      $values->{'response'}{'xframeopt'} ne ''
    ) {
      $values->{'grades'}->{'frames'} = 0.5;
      $grade += 0.5;
    }
    $max_grade += 0.5;

    ## Country
    # GeoIP isn't reliable.
    #$values->{'grades'}->{'country'} = 0;
    #if ($values->{'country'}->{'code'} eq 'CH') {
    #  $grade += 1;
    #  $values->{'grades'}->{'country'} = 1;
    #} elsif($values->{'country'}->{'code'} =~ /US|UK|GB|AU|NZ|CA/) {
    #  $grade -= 1;
    #  $values->{'grades'}->{'country'} = -1;
    #}
    #$max_grade += 1;


    $values->{'grades'}->{'total'} = $grade;
    $values->{'grades'}->{'max'} = $max_grade;
  }

  return \%output;
}

# we want to keep only some elements.
# for example, we want to remove the rejectedCipherSuites
# as there is no use for our purpose.
sub cleanJson {
  my ($json) = @_;

  delete $json->{'results'}->{'startTLS'};
  delete $json->{'results'}->{'httpsTunnel'};
  delete $json->{'results'}->{'defaultTimeout'};
  delete $json->{'results'}->{'invalidTargets'};

  eval {
    my @array = @{$json->{'results'}->{'target'}} ;

    foreach my $el (@array) {
      delete $el->{'sslv2'}->{'rejectedCipherSuites'};
      delete $el->{'sslv3'}->{'rejectedCipherSuites'};
      delete $el->{'tlsv1'}->{'rejectedCipherSuites'};
      delete $el->{'tlsv1_1'}->{'rejectedCipherSuites'};
      delete $el->{'tlsv1_2'}->{'rejectedCipherSuites'};
    }
    1;
  } or do {
    my $el = $json->{'results'}->{'target'};
    delete $el->{'sslv2'}->{'rejectedCipherSuites'};
    delete $el->{'sslv3'}->{'rejectedCipherSuites'};
    delete $el->{'tlsv1'}->{'rejectedCipherSuites'};
    delete $el->{'tlsv1_1'}->{'rejectedCipherSuites'};
    delete $el->{'tlsv1_2'}->{'rejectedCipherSuites'};
  };

  return compute($json);
}

# remove trailing and leading spaces
sub trim {
  my ($string) = @_;
  $string =~ s/^\s+|\s+$//gm;
  return $string;
}
