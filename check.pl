#!/usr/bin/perl

use warnings;
use strict;
use Data::Dumper;
use Text::CSV;
use LWP::UserAgent;
use IO::Socket::SSL;
use IO::Socket::SSL::Utils;
use Net::SSLeay qw(get_https3);
use Net::DNS;
use Net::Whois::IP qw(whoisip_query);
use Term::ANSIColor qw(:constants);
use JSON;
use List::MoreUtils qw(first_index);

use Net::Whois::IP qw(whoisip_query);

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

open my $fh,  '<', $file || die $!;

my ($front, $ebanking);
my @output = ();

while(my $row = $csv->getline($fh)) {
  if (scalar @{$row} == 2) {
    # test e-banking
    $front    = $row->[0];
    $ebanking = $row->[1];
    push @output, check($front);

    if ($front ne $ebanking) {
      push @output, check($ebanking);
    }
  } else {
    # e-banking through dedicated app
    $front  = $row->[0];
    push @output, check($front);
  }
}
close $file;

open FH, '>output.json' || die $!;
my $json = JSON->new;
print FH $json->pretty->encode(\@output);
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
  my $redirect;
  print "  redirection:";
  if ($res_code == 302 || $res_code == 301) {
    print GREEN,BOLD " OK\n", RESET;
    $redirect = 'yes';
  } else {
    print RED,BOLD " NOK", RESET;
    print " (${res_code})\n";
    $redirect = 'no';
  }

  check_ssl($host, $redirect);
}

sub check_ssl {
  my ($host, $redirect) = @_;

  my @ssl_versions = (
    'SSLv3',
    'TLSv1',
    'TLSv11',
    'TLSv12',
  );
  my %ssl_ciphers = (
    weak => [
      '3DES',
      'ADH',
      'AECDH-NULL-SHA',
      'aNULL',
      'CAMELLIA',
      'DES',
      'EDH-RSA-DES-CBC-SHA',
      'eNULL',
      'EXP',
      'EXPORT40',
      'EXPORT56',
      'kECDH',
      'KRB5',
      'LOW',
      'MD5',
      'PSK',
      'RC4',
      'RC2',
      'SHA',
      'SRP',
    ],
    good => [
      'AES',
      'EECDH',
      'EDH-aRSA',
      'HIGH',
      'SHA256',
    ],
  );

  my $sock;
  my $cert_checks = 0;
  my (
    $certificate,
    $cipher,
    $ciphers_list,
    $default_cipher,
    $hash,
    $level,
  );
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
      push  $accepted_protocols, $ssl_version ;
      print " (with ".$default_cipher.")\n";

      $good_ciphers->{$ssl_version} = [];
      $weak_ciphers->{$ssl_version} = [];
      while (($level, $ciphers_list) = each(%ssl_ciphers)) {
        foreach $cipher (@{$ciphers_list}) {
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
            SSL_verifycn_scheme => 'http'
          );
          if ($sock && $sock->opened) {
            if ($level eq 'weak') {
              print RED "    ${cipher} OK (weak)\n", RESET;
              push  $weak_ciphers->{$ssl_version}, $cipher;
            } else {
              print GREEN "    ${cipher} OK (good)\n", RESET;
              push  $good_ciphers->{$ssl_version}, $cipher;
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

  $hash = {
    host           => $host,
    ips            => $ips,
    redirect       => $redirect,
    ciphers        => {
      good         => $good_ciphers,
      weak         => $weak_ciphers
    },
    certificate    => $certificate,
    protocols      => $accepted_protocols,
    default_cipher => $default_cipher,
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
