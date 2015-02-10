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
  print RED,BOLD "!!! Creating new JSON !!!\n\n", RESET;
  $json = {};
}


$json->{'version'} = $json_version->stringify();
$json->{'date'} = $date;

open my $fh,  '<:encoding(utf8)', $url_file or die $!;
my ($front, $ebanking, $bank_name);
while(my $row = $csv->getline($fh)) {
  $bank_name = trim($row->[0]);
  $front = trim($row->[1]);

  if ($bank_name !~ /^#/) {

    if (!exists $json->{$front} || $refresh) {
      #$json->{$front} = check($front, 'front', '', $refresh);
      #$json->{$front}->{'role'} = 'front';
      #$json->{$front}->{'bank_name'} = $bank_name;

      if (scalar @{$row} == 3) {
        $ebanking = trim($row->[2]);
        if ($front ne $ebanking) {
          sslyze($refresh, $bank_name, $front, $ebanking);
        } else {
          #$json->{$front}->{'ebanking'} = 'self';
          sslyze($refresh, $bank_name, $front);
        }
      } else {
        sslyze($refresh, $bank_name, $front);
        #$json->{$front}->{'ebanking'} = 'app';
      }
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

  xml2json($xml_out);
}

sub xml2json {
  my ($xml_file) = @_;

  my $xml = new XML::Simple;
  my $data = $xml->XMLin($xml_file);

  my $XML2JSON = XML::XML2JSON->new();
  $XML2JSON->sanitize($data);
  my $JSON = $XML2JSON->obj2json($data);

}


sub trim {
  my ($string) = @_;
  $string =~ s/^\s+|\s+$//gm;
  return $string;
}
