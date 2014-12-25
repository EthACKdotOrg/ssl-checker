#!/usr/bin/env perl

use warnings;
use strict;
use Data::Dumper;
use Text::CSV;
use LWP::UserAgent;
use IO::Socket::SSL;
use Net::SSLeay qw(get_https3);
use Net::DNS;
use Net::Whois::IP qw(whoisip_query);
use Term::ANSIColor qw(:constants);
use JSON;
use List::MoreUtils qw(first_index);
use Perl::Version;
use POSIX qw/strftime/;


use lib 'lib';
use ssl::heartbleed qw(check_heartbleed);

my $file = './urls';
my $csv = Text::CSV->new();

my @useragents = (
  'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0',
  'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0',
  'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0',
  'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0',
  'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0;  rv:11.0) like Gecko',
  'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
  'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
  'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)',
  'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)',
);


my $json_obj = JSON->new;
my $json_output = 'output.json';
my $json = {};
my $json_version = Perl::Version->new('1.0.2');

if (-e $json_output) {
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

my $date = strftime "%y-%m-%d", localtime;

$json->{'version'} = $json_version->stringify();
$json->{'date'} = $date;

open my $fh,  '<', $file or die $!;
my ($front, $ebanking, $bank_name);
while(my $row = $csv->getline($fh)) {
  $bank_name = $row->[0];
  $front = $row->[1];

  if (!exists $json->{$front}) {
    $json->{$front} = check($front, 'front');
    $json->{$front}->{'role'} = 'front';
    $json->{$front}->{'bank_name'} = $bank_name;
  } else {
    print "\n${front} already done\n";
  }
  
  if (scalar @{$row} == 3) {
    $ebanking = $row->[2];
    if ($front ne $ebanking) {
      if (!exists $json->{$ebanking}) {
        $json->{$ebanking} = check($ebanking, 'ebanking', $front);
        $json->{$ebanking}->{'role'} = 'ebanking';
        $json->{$ebanking}->{'bank'} = $front;
        $json->{$ebanking}->{'bank_name'} = $bank_name;

        $json->{$front}->{'ebanking'} = $ebanking;
      } else {
        print "\n${ebanking} already done\n";
      }
    } else {
      $json->{$front}->{'ebanking'} = 'self';
    }
  } else {
    $json->{$front}->{'ebanking'} = 'app';
  }
}
close $file;

open FH, '>', $json_output or die $!;
print FH $json_obj->pretty->encode($json);
close FH;

sub check {
  my ($host) = @_;

  print "Checking: ${host}\n";

  # are we sent to SSL web page?
  my $agent = $useragents[rand @useragents];
  my $ua = LWP::UserAgent->new();
  # deactivate redirection
  $ua->requests_redirectable(undef);
  $ua->timeout(5);
  $ua->agent($agent);

  my $req = HTTP::Request->new('GET',"http://${host}/");
  my $res = $ua->request($req);
  my $res_code = $res->code();
  my $no_ssl_hash = {
    redirect_ssl  => '',
    redirect_code => 0,
    redirect_to   => '',
    clear_access  => 'yes',
  };
  print "  HTTP access:";

  $no_ssl_hash->{'clear_access'} = 'yes';
  
  if ($res_code == 200) {
    print RED,BOLD " OK\n", RESET;
  } elsif ($res_code == 500) {
    print GREEN,BOLD " NO clear access", RESET;
    print " (timeout)\n";
    $no_ssl_hash->{'clear_access'} = 'no';
  } else {
    print RED,BOLD " OK, with redirection(s)", RESET;
    print " (${res_code})\n";
  }

  check_ssl($host, $no_ssl_hash);
}

sub check_ssl {
  my ($host, $no_ssl_hash) = @_;

  my @ssl_versions = (
    'SSLv3',
    'TLSv1',
    'TLSv11',
    'TLSv12',
  );
  my %ssl_ciphers = (
# https://www.websense.com/support/article/kbarticle/Security-Vulnerability-Weak-Supported-SSL-Cypher-Suites-for-Apache-HTTPD-server
    weak => {
      '3DES'                    => 'no_pfs',
      'ADH'                     => 'no_pfs',
      'AECDH-NULL-SHA'          => 'no_pfs',
      'aNULL'                   => 'no_pfs',
      'DES'                     => 'no_pfs',
      'EDH-RSA-DES-CBC-SHA'     => 'no_pfs',
      'eNULL'                   => 'no_pfs',
      'EXP'                     => 'no_pfs',
      'EXP-EDH-RSA-DES-CBC-SHA' => 'pfs',
      'EXP-DES-CBC-SHA'         => 'no_pfs',
      'EXP-RC2-CBC-MD5'         => 'no_pfs',
      'EXP-RC4-MD5'             => 'no_pfs',
      'EXP-EDH-RSA-DES-CBC-SHA' => 'pfs',
      'EXP-DES-CBC-SHA'         => 'no_pfs',
      'EXP-RC2-CBC-MD5'         => 'no_pfs',
      'EXP-RC4-MD5'             => 'no_pfs',
      'EXPORT40'                => 'no_pfs',
      'EXPORT56'                => 'no_pfs',
      'kECDH'                   => 'no_pfs',
      'KRB5'                    => 'no_pfs',
      'LOW'                     => 'no_pfs',
      'MD5'                     => 'no_pfs',
      'PSK'                     => 'no_pfs',
      'RC4'                     => 'no_pfs',
      'RC2'                     => 'no_pfs',
      'SHA1'                    => 'no_pfs',
      'SRP'                     => 'no_pfs',
    },
# https://alpacapowered.wordpress.com/2014/12/15/cipher-suite-for-qualys-ssl-labs-server-test-aa-rating/
    good => {
      'ECDHE-RSA-AES256-GCM-SHA384'     => 'pfs',
      'ECDHE-ECDSA-AES256-GCM-SHA384'   => 'pfs',
      'ECDHE-RSA-AES256-SHA384'         => 'pfs',
      'ECDHE-ECDSA-AES256-SHA384'       => 'pfs',
      'ECDHE-RSA-AES256-SHA'            => 'pfs',
      'ECDHE-ECDSA-AES256-SHA'          => 'pfs',
      'DHE-DSS-AES256-GCM-SHA384'       => 'pfs',
      'DHE-RSA-AES256-GCM-SHA384'       => 'pfs',
      'DHE-RSA-AES256-SHA256'           => 'pfs',
      'DHE-DSS-AES256-SHA256'           => 'pfs',
      'DHE-RSA-AES256-SHA'              => 'pfs',
      'DHE-DSS-AES256-SHA'              => 'pfs',
      'AES256-GCM-SHA384'               => 'no_pfs',
      'AES256-SHA256'                   => 'no_pfs',
      'AES256-SHA'                      => 'no_pfs',
      'ECDHE-RSA-AES128-GCM-SHA256'     => 'pfs',
      'ECDHE-ECDSA-AES128-GCM-SHA256'   => 'pfs',
      'ECDHE-RSA-AES128-SHA256'         => 'pfs',
      'ECDHE-ECDSA-AES128-SHA256'       => 'pfs',
      'ECDHE-RSA-AES128-SHA'            => 'pfs',
      'ECDHE-ECDSA-AES128-SHA'          => 'pfs',
      'DHE-DSS-AES128-GCM-SHA256'       => 'pfs',
      'DHE-RSA-AES128-GCM-SHA256'       => 'pfs',
      'DHE-RSA-AES128-SHA256'           => 'pfs',
      'DHE-DSS-AES128-SHA256'           => 'pfs',
      'DHE-RSA-AES128-SHA'              => 'pfs',
      'DHE-DSS-AES128-SHA'              => 'pfs',
      'AES128-GCM-SHA256'               => 'no_pfs',
      'AES128-SHA256'                   => 'no_pfs',
      'AES128-SHA'                      => 'no_pfs',
    },
  );

  my $sock;
  my $cert_checks = 0;
  my (
    $certificate,
    $cipher,
    $ciphers_list,
    $default_cipher,
    $hash,
    $heart_code,
    $heart_msg,
    $level,
    $pfs,
  ) = '';
  my $accepted_protocols = [];
  my $good_ciphers = {};
  my $weak_ciphers = {};

  foreach my $ssl_version (@ssl_versions) {
    $sock = IO::Socket::SSL->new(
      # where to connect
      PeerHost => $host,
      PeerPort => "https",

      SSL_version            => $ssl_version,
      SSL_honor_cipher_order => 0,

      # certificate verification
      SSL_verify_mode => SSL_VERIFY_PEER,
      SSL_ca_path     => '/etc/ssl/certs', # typical CA path on Linux
      SSL_verifycn_scheme => 'http'
    );

    if ($sock && $sock->opened) {

      if (!$cert_checks) {
        $certificate = check_cert($host);
        $cert_checks = 1;
      }
      $default_cipher = $sock->get_cipher();

      $sock->close();


      print "  Trying ";
      print BOLD $ssl_version, RESET;
      if ($ssl_version eq 'SSLv3') {
        print RED " success", RESET;
      } else {
        print GREEN " success", RESET;
      }
      push @{$accepted_protocols}, $ssl_version ;
      print " (with ".$default_cipher.")\n";

      # heartbleed
      print "  Checking Heartbleed…";
      ($heart_code, $heart_msg) = check_heartbleed($host, lc($ssl_version) );
      print " ${heart_msg}\n";

      $good_ciphers->{$ssl_version} = [];
      $weak_ciphers->{$ssl_version} = [];
      while (($level, $ciphers_list) = each(%ssl_ciphers)) {
        while (($cipher, $pfs) = each (%{$ciphers_list})) {
          $sock = IO::Socket::SSL->new(
            # where to connect
            PeerHost => $host,
            PeerPort => "https",

            SSL_version            => $ssl_version,
            SSL_honor_cipher_order => 0,
            SSL_cipher_list        => $cipher,
            # certificate verification
            SSL_verify_mode => SSL_VERIFY_PEER,
            SSL_ca_path     => '/etc/ssl/certs', # typical CA path on Linux
            SSL_verifycn_scheme => 'http',

            Timeout => 3,
          );
          if ($sock && $sock->opened) {
            if ($level eq 'weak') {
              print RED "    ${cipher} OK (weak, ${pfs})\n", RESET;
              push  @{$weak_ciphers->{$ssl_version}}, {cipher => $cipher, pfs => $pfs};
            } else {
              print GREEN "    ${cipher} OK (good, ${pfs})\n", RESET;
              push  @{$good_ciphers->{$ssl_version}}, {cipher => $cipher, pfs => $pfs};
            }
            $sock->close();
          }
        }
      }

    } else {
      print "  Trying ";
      print BOLD $ssl_version, RESET;
      if ($ssl_version eq 'SSLv3') {
        print GREEN " failed\n", RESET;
      } else {
        print RED " failed\n", RESET;
      }
    }
  }

  my $resolver = Net::DNS::Resolver->new;
  my $query = $resolver->search($host);
  my $ips = {};
  my $search_options = ["NetName","OrgName"];
  my $resp;
  if ($query) {
    foreach my $rr ($query->answer) {
      next unless $rr->type eq 'A';
      $resp = whoisip_query($rr->address, '', $search_options);
      $ips->{$rr->address} = $resp;
    }
  }

  my $check_server = check_server($host);

  $hash = {
    certificate    => $certificate,
    ciphers        => {
      good         => $good_ciphers,
      weak         => $weak_ciphers
    },
    default_cipher => $default_cipher,
    ips            => $ips,
    no_ssl         => $no_ssl_hash,
    protocols      => $accepted_protocols,
    server_info    => $check_server,
    ssl_cves       => {
      'heartbleed' => {code => $heart_code, msg => $heart_msg},
    },
  };

  return $hash;
}

sub check_cert {
  my ($host) = @_;
  my ($p, $resp, $hdrs, $server_cert) = get_https3($host, 443, '/');
  
  my $issuer = Net::SSLeay::X509_NAME_oneline(
    Net::SSLeay::X509_get_issuer_name($server_cert)
  );
  my $subject = Net::SSLeay::X509_NAME_oneline(
    Net::SSLeay::X509_get_subject_name($server_cert)
  );
  my $not_before = Net::SSLeay::P_ASN1_TIME_get_isotime(
    Net::SSLeay::X509_get_notBefore($server_cert)
  );
  my $not_after = Net::SSLeay::P_ASN1_TIME_get_isotime(
    Net::SSLeay::X509_get_notAfter($server_cert)
  );
  my @altnames = Net::SSLeay::X509_get_subjectAltNames($server_cert);
  my $key_alg = Net::SSLeay::OBJ_obj2txt(Net::SSLeay::P_X509_get_pubkey_alg($server_cert));
  my $sign_alg = Net::SSLeay::OBJ_obj2txt(Net::SSLeay::P_X509_get_signature_alg($server_cert));


  my $match_root;
  if ($host =~ /^www\./) {
    my $_host = substr $host, 4;
    if (first_index { $_ eq $_host } @altnames) {
      print GREEN "  Certificate matches ${_host}, good\n", RESET;
      $match_root = 'yes';
    } else {
      print RED "  Certificate does NOT match ${_host}, confusing\n", RESET;
      $match_root = 'no';
    }
  } else {
    $match_root = 'Not for subdomains';
  }

  return {
    alt_names  => \@altnames,
    issuer     => $issuer,
    key_algo   => $key_alg,
    match_top  => $match_root,
    subject    => $subject,
    not_before => $not_before,
    not_after  => $not_after,
    sign_algo  => $sign_alg,
  };
}

sub check_server {
  my ($host) = @_;

  if (!-e "./jsons/${host}.json") {
    my $agent = $useragents[rand @useragents];
    system('./external/whatweb/whatweb', '-q', '-a=3', "-U='${agent}'", "--log-json=./jsons/${host}.json", $host);
    open FHT, '<', "./jsons/${host}.json" or die $!;
    if (scalar @{[<FHT>]} == 0) {
      print "  Trying SSL…\n";
      system('./external/whatweb/whatweb', '-q', '-a=3', "-U='${agent}'", "--log-json=./jsons/${host}.json", "https://${host}");
    }
    close FHT;
  }

  my $list = [];
  my $json = JSON->new;
  open FH, '<', "./jsons/${host}.json" or die $!;
  while (<FH>) {
    push @$list, $json->decode($_);
  }
  close FH;
  return $list;
}
