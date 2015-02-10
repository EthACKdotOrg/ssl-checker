#!/usr/bin/env perl

use warnings;
use strict;
use Data::Dumper;
use Text::CSV;
use Perl::Version;
use POSIX qw/strftime/;
use Time::ParseDate;
use Getopt::Long;
use File::Spec;
use Term::ANSIColor qw(:constants);
use JSON;
use Digest::SHA;
use XML::XML2JSON;
use XML::Simple;

use lib 'lib';
use checks;


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
      $json->{$bank_name}->{'frontend'} = $front;

      if (scalar @{$row} == 3) {
        $ebanking = trim($row->[2]);
        if ($front ne $ebanking) {
          $result = sslyze($refresh, $bank_name, $front, $ebanking);
          $json->{$bank_name}->{'backend'} = $ebanking;
        } else {
          $result = sslyze($refresh, $bank_name, $front);
          $json->{$bank_name}->{'backend'} = 'self';
        }
      } else {
        $result = sslyze($refresh, $bank_name, $front);
        $json->{$bank_name}->{'backend'} = 'app';
      }
      $json->{$bank_name}->{'results'} = $result;
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

  my $xml_out = File::Spec->catfile('xmls', "${digest}.xml");

  if (!-e $xml_out || $refresh) {

    my @cmd = (
      './external/sslyze/sslyze.py', 
      '--regular',
      '--xml_out',
      $xml_out,
      '--sni',
      $frontend,
      $frontend,
    );
    if ($backend) {
      push @cmd, '--sni', $backend, $backend;
    }

    system(@cmd);
  }

  return xml2json($xml_out);
}

# do some computations based on the results we got from sslyze
# also, fetch some other information in order to find more stuff
sub compute {
  my ($json) = @_;

  my %output;

  # multiple target?
  eval {
    my @array = @{$json->{'results'}->{'target'}} ;
    foreach my $el (@array) {
      $output{$el->{'host'}}{'sslv2'} = has_sslv2($el);
      $output{$el->{'host'}}{'sslv3'} = has_sslv3($el);
      $output{$el->{'host'}}{'rc4'}   = has_rc4($el);
      $output{$el->{'host'}}{'des'}   = has_des($el);
      $output{$el->{'host'}}{'md5'}   = has_md5($el);
      $output{$el->{'host'}}{'null'}  = has_null($el);
    }
    1;
  } or do {
    my $el = $json->{'results'}->{'target'};
    $output{$el->{'host'}}{'sslv2'} = has_sslv2($el);
    $output{$el->{'host'}}{'sslv3'} = has_sslv3($el);
    $output{$el->{'host'}}{'rc4'}   = has_rc4($el);
    $output{$el->{'host'}}{'des'}   = has_des($el);
    $output{$el->{'host'}}{'md5'}   = has_md5($el);
    $output{$el->{'host'}}{'null'}  = has_null($el);
  };

  $json->{'results'}->{'grades'} = \%output;

  return $json;
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

# convert sslyze XML to JSON
sub xml2json {
  my ($xml_file) = @_;

  my $xml = new XML::Simple;
  my $data = $xml->XMLin($xml_file);

  my $xml2js = XML::XML2JSON->new();
  #$xml2js->sanitize($data);
  my $json_str = $xml2js->obj2json($data);

  my $json_obj = JSON->new;
  $json_obj->utf8(1);

  my $json = $json_obj->decode($json_str);
  return cleanJson($json);
}

# remove trailing and leading spaces
sub trim {
  my ($string) = @_;
  $string =~ s/^\s+|\s+$//gm;
  return $string;
}
