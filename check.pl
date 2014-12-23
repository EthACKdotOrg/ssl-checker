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

open my $fh,  '<', $file or die $!;

my ($front, $ebanking);
my $output = {};

while(my $row = $csv->getline($fh)) {
  $front = $row->[0];

  $output->{$front} = check($front, 'front');
  $output->{$front}->{'role'} = 'front';
  
  if (scalar @{$row} == 2) {
    $ebanking = $row->[1];
    if ($front ne $ebanking) {
      $output->{$ebanking} = check($ebanking, 'ebanking', $front);
      $output->{$ebanking}->{'role'} = 'ebanking';
      $output->{$ebanking}->{'bank'} = $front;

      $output->{$front}->{'ebanking'} = $ebanking;
    } else {
      $output->{$front}->{'ebanking'} = 'self';
    }
  } else {
    $output->{$front}->{'ebanking'} = 'app';
  }
}
close $file;

open FH, '>output.json' or die $!;
my $json = JSON->new;
print FH $json->pretty->encode($output);
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
  print "  redirection:";
  if ($res_code == 302 || $res_code == 301) {
    
    $no_ssl_hash->{'redirect_to'} = $res->header('location');
    $no_ssl_hash->{'redirect_code'} = $res_code;

    if ($res->header('location') =~ /https:\/\/${host}\//) {
      print GREEN,BOLD " OK\n", RESET;
      $no_ssl_hash->{'redirect_ssl'} = 'yes';
    } else {
      print RED,BOLD " NOK", RESET;
      $no_ssl_hash->{'redirect_ssl'} = 'no';
    }
  } elsif ($res_code == 500) {
    print RED,BOLD " NO clear access", RESET;
    print " (timeout)\n";
    $no_ssl_hash->{'clear_access'} = 'no';
  } else {
    print RED,BOLD " NOK", RESET;
    print " (${res_code})\n";
    $no_ssl_hash->{'redirect_ssl'} = 'no';
    $no_ssl_hash->{'redirect_code'} = $res_code;
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
              push  @{$weak_ciphers->{$ssl_version}}, {$cipher => $pfs};
            } else {
              print GREEN "    ${cipher} OK (good, ${pfs})\n", RESET;
              push  @{$good_ciphers->{$ssl_version}}, {$cipher => $pfs};
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

  my $agent = $useragents[rand @useragents];
  my $ua = LWP::UserAgent->new();
  # deactivate redirection
  $ua->requests_redirectable(undef);
  $ua->timeout(5);
  $ua->agent($agent);

  my $url = "https://${host}/";
  my $res = $ua->head($url);

  return {
    hsts   => ($res->header('strict-transport-security') || 'not set'),
    csp    => ($res->header('content-security-policy') || 'not set'),
    server => ($res->header('server') || 'unknown'),
    xframe => ($res->header('x-frame-options') || 'not set'),
  };
}
