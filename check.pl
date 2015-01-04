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
use List::MoreUtils qw(first_index zip);
use Perl::Version;
use POSIX qw/strftime/;
use Time::ParseDate;
use Getopt::Long;
use File::Spec;


my $url_file = './urls';
my $output_dir = './';
my $refresh = '';

GetOptions (
  'output=s' => \$output_dir,
  'refresh'  => \$refresh,
  'urls=s'   => \$url_file,
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



use lib 'lib';
use ssl::heartbleed qw(check_heartbleed);
#use ssl::beast qw(check_beast);

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
$json_obj->utf8(1);
my $json = {};
my $json_version = Perl::Version->new('2.0.0');
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
  $bank_name = $row->[0];
  $front = $row->[1];

  if (!exists $json->{$front} || $refresh) {
    $json->{$front} = check($front, 'front', '', $refresh);
    $json->{$front}->{'role'} = 'front';
    $json->{$front}->{'bank_name'} = $bank_name;
  }

  if (scalar @{$row} == 3) {
    $ebanking = $row->[2];
    if ($front ne $ebanking) {
      if (!exists $json->{$ebanking} || $refresh) {
        $json->{$ebanking} = check($ebanking, 'ebanking', $front, $refresh);
        $json->{$ebanking}->{'role'} = 'ebanking';
        $json->{$ebanking}->{'bank'} = $front;
        $json->{$ebanking}->{'bank_name'} = $bank_name;

        $json->{$front}->{'ebanking'} = $ebanking;
      }
    } else {
      $json->{$front}->{'ebanking'} = 'self';
    }
  } else {
    $json->{$front}->{'ebanking'} = 'app';
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

sub check {
  my ($host, $role, $frontal, $refresh) = @_;

  print "Checking: ${host} (${role})\n";

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

  if ($res_code >= 500) {
    $no_ssl_hash->{'clear_access'} = 'no';
  }

  check_ssl($host, $no_ssl_hash, $role, $refresh);
}

sub check_ssl {
  my ($host, $no_ssl_hash, $role, $refresh) = @_;

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
    $beast_code,
    $beast_msg,
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
      SSL_honor_cipher_order => 1,

      # certificate verification
      SSL_verify_mode => SSL_VERIFY_NONE,
      SSL_ca_path     => '/etc/ssl/certs', # typical CA path on Linux
      #SSL_verifycn_scheme => 'http'
    );

    if ($sock && $sock->opened) {

      print $sock "GET / HTTP/1.0\r\n\r\n";

      if (!$cert_checks) {
        $certificate = check_cert($host);
        $cert_checks = 1;
      }
      $default_cipher = $sock->get_cipher();

      $sock->close(SSL_ctx_free => 1);


      push @{$accepted_protocols}, $ssl_version ;

      # heartbleed
      ($heart_code, $heart_msg) = check_heartbleed($host, lc($ssl_version) );
      #print "  Checking BEAST…";
      #($beast_code, $beast_msg) = check_beast($host);
      #print " ${beast_status}\n";

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
              push  @{$weak_ciphers->{$ssl_version}}, {cipher => $cipher, pfs => $pfs};
            } else {
              push  @{$good_ciphers->{$ssl_version}}, {cipher => $cipher, pfs => $pfs};
            }
            $sock->close(SSL_ctx_free => 1);
          }
        }
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

  my $check_server = check_server($host, $refresh);

  my $result = 0;
  my $max_result = 0;

  ## PROCESS result
  # certificate:
  #     - front invalid: -1
  #     - ebanking invalid: -2

  my $end_certificate = parsedate($certificate->{'not_after'});
  my $certif_pts = 0;
  if (scalar @$accepted_protocols > 0) {
    if ($end_certificate < time()) {
      if ($role eq 'ebanking') {
        $result -= 2;
        $certif_pts = -2;
      } else {
        $result -= 1;
        $certif_pts = -1;
      }
    }
  }

  #
  # ciphers:
  #     - majority of strong ciphers: +2
  #     - majority of weak ciphers: 0

  my @weak   = get_ciphers($weak_ciphers);
  my @strong = get_ciphers($good_ciphers);
  # ponderation
  my $strongs = scalar (keys %{$ssl_ciphers{'good'}});
  my $weaks = scalar (keys %{$ssl_ciphers{'weak'}});

  my $ponderation = ($weaks*100/$strongs);
  my $percent_weak = ( (scalar @{$weak[0]}) * $ponderation / $weaks );
  my $percent_strong = ( (scalar @{$strong[0]}) * 100 / $strongs );

  my $cipher_pts = 0;
  if ($percent_strong > $percent_weak) {
    $result += 2;
    $cipher_pts = 2;
  }
  $max_result += 2;


  # country:
  #     - CH: +2
  #     - US/UK: -1
  #     - Other: 1

  my $last_redirect = $check_server->[$#{$check_server}];

  my $country = '';

  while(my ($ip, $data) = each(%$ips)) {
    if (exists $data->{'country'}) {
      $country = $data->{'country'};
    } elsif(exists $data->{'Country'}) {
      $country = $data->{'Country'};
    }
  }
  if ($country eq '') {
    if ($last_redirect->{'plugins'}->{'Country'}) {
      $country = $last_redirect->{'plugins'}->{'Country'}->{'module'};
    }
  }
  my $country_pts = 0;

  if ($country eq 'CH' || lc $country eq 'switzerland') {
    $result += 2;
    $country_pts = 2;
  } elsif (
    $country eq 'GB'  ||
    $country eq 'UK'  ||
    $country eq 'US'  ||
    $country eq 'USA'
  ) {
    $result -= 1;
    $country_pts = -1;
  } else {
    $result += 1;
    $country_pts = 1;
  }
  $max_result += 2;

  #
  # flash:
  #     - present on front: -1
  #     - present on ebanking: -2

  my $flash_pts = 0;
  if ($last_redirect->{'plugins'}->{'Adobe-Flash'}) {
    if ($role eq 'ebanking') {
      $result -= 2;
      $flash_pts = -2;
    } else {
      $result -= 1;
      $flash_pts = -1;
    }
  }

  #
  # frames:
  #     - unprotected on front: -1
  #     - unprotected on ebanking: -2

  my $frame_pts = 0;
  my $frame_expl = 'no';
  if (exists $last_redirect->{'plugins'}->{'Frame'}) {
    $frame_expl = 'yes';
    if ($last_redirect->{'plugins'}->{'X-Frame-Options'}) {
      if (!grep {$_ eq 'SAMEORIGIN'} @{$last_redirect->{'plugins'}->{'X-Frame-Options'}->{'string'}}) {
        if ($role eq 'ebanking') {
          $result -= 2;
          $frame_pts = -2;
        } else {
          $result -= 1;
          $frame_pts = -1;
        }
      }
    } else {
      if ($role eq 'ebanking') {
        $result -= 2;
        $frame_pts = -2;
      } else {
        $result -= 1;
        $frame_pts = -1;
      }
    }
  }

  #
  # pfs:
  #     - majority of ciphers with PFS:
  #             - over 60%: +2
  #             - else: +1
  #     - majority of ciphers without PFS: -1

  my $pfs_weaks   = count_pfs($ssl_ciphers{'weak'});
  my $pfs_strongs = count_pfs($ssl_ciphers{'good'});

  $ponderation = ($pfs_weaks*100/$pfs_strongs);
  my $percent_weak_pfs = ( (scalar $weak[1]) * $ponderation / $pfs_weaks );
  my $percent_strong_pfs = ( (scalar $strong[1]) * 100 / $pfs_strongs );

  my $cipher_pfs_pts = 0;
  if ($percent_strong_pfs > $percent_weak_pfs) {
    if ($percent_strong_pfs > 60) {
      $result += 2;
      $cipher_pfs_pts = 2;
    } else {
      $result += 1;
      $cipher_pfs_pts = 1;
    }
  }
  $max_result += 2;

  #
  # protocols:
  #     - if SSLv3 absent
  #             - if only TLSv1: +1
  #             - if TLSv1, 11, 12: +2
  #     - if SSLv3 present
  #             - if only TLSv1: 0
  #             - if TLSv1,11,12: +1
  #     - if only SSLv3 or no SSL:
  #             - front: -1
  #             - ebanking: -2

  my $protocols_pts = 0;
  if (scalar @$accepted_protocols > 0) {
    if (grep {$_ eq 'SSLv3'} @$accepted_protocols) {
      if (scalar @$accepted_protocols == 1) {
        if ($role eq 'ebanking') {
          $result -= 2;
          $protocols_pts = -2;
        } else {
          $result -= 1;
          $protocols_pts = -1;
        }
      } elsif (scalar @$accepted_protocols == 2) {
        $result += 1;
        $protocols_pts = 1;
      } else {
        $result += 2;
        $protocols_pts = 2;
      }
    } else {
      if (scalar @$accepted_protocols == 1 && grep {$_ eq 'TLSv1'} @$accepted_protocols) {
        $protocols_pts = 0;
      } else {
        $result += 2;
        $protocols_pts = 2;
      }
    }
  } else {
    if ($role eq 'ebanking') {
      $result -= 2;
      $protocols_pts = -2;
    } else {
      $result -= 1;
      $protocols_pts = -1;
    }
  }
  $max_result += 2;

  #
  # server:
  #     - no point

  my $server = 'unknown';
  if ($last_redirect->{'plugins'}->{'HTTPServer'}) {
    $server = $last_redirect->{'plugins'}->{'HTTPServer'}->{'string'}->[0];
  }

  #
  # ssl:
  #     - redirected: +2
  #     - only: +2
  #     - optional: +1
  #     - absent: -1

  my $ssl_pts = 0;
  my $ssl_expl;
  if ($no_ssl_hash->{'clear_access'}) {
    if ($last_redirect->{'target'} =~ /^https:/) {
      $result += 2;
      $ssl_pts = 2;
      $ssl_expl = 'forced';
    } elsif(scalar $accepted_protocols == 0) {
      $result += -1;
      $ssl_pts = -1;
      $ssl_expl = 'absent';
    } else {
      $result += 1;
      $ssl_pts = 1;
      $ssl_expl = 'optional';
    }
  } else {
    $result += 2;
    $ssl_pts = 2;
    $ssl_expl = 'only';
  }
  $max_result += 2;

  #
  # trackers:
  #     -1 per detected tracker

  my $trackers_pts = 0;
  my $trackers = ();
  if ($last_redirect->{'plugins'}->{'Google-Analytics'}) {
    $result -= 1;
    $trackers_pts -= 1;
    push @$trackers, 'Google Analytics';
  }

  if ($last_redirect->{'plugins'}->{'Google-API'}) {
    $result -= 1;
    $trackers_pts += 1;
    push @$trackers, 'Google API';
  }
  


  $hash = {
    ssl_cves       => {
      'heartbleed' => {code => $heart_code, msg => $heart_msg},
      #'beast'      => {code => $beast_code, msg => $beast_msg},
    },
    evaluation     => {
      result       => $result,
      max_result   => $max_result,
      detail       => {
        cert       => { points => $certif_pts, expl => $certificate->{'not_after'}},
        ciphers    => {
          points   => $cipher_pts,
          expl     => {weak => $percent_weak, strong => $percent_strong},
          weak     => $weak_ciphers,
          strong   => $good_ciphers
        },
        country    => { points => $country_pts, expl => $country},
        flash      => { points => $flash_pts, expl => ''},
        frames     => { points => $frame_pts, expl => $frame_expl},
        pfs        => { points => $cipher_pfs_pts, expl => '', weak => $percent_weak_pfs, strong => $percent_strong_pfs},
        protocols  => { points => $protocols_pts, expl => $accepted_protocols},
        server     => { points => 0, expl => $server},
        ssl        => { points => $ssl_pts, expl => $ssl_expl},
        trackers   => { points => $trackers_pts, expl => $trackers},
      },
    },
    ips            => $ips,
    #certificate    => $certificate,
    #ciphers        => {
    #  good         => $good_ciphers,
    #  weak         => $weak_ciphers
    #},
    #default_cipher => $default_cipher,
    #no_ssl         => $no_ssl_hash,
    #protocols      => $accepted_protocols,
    #server_info    => $check_server,
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

  my $match_cn = 'no';
  if (grep {$_ eq $host} @altnames) {
    $match_cn = 'yes';
  } elsif (grep {$_ =~ /^\*\.${host}$/} @altnames) {
    $match_cn = 'wildcard';
  }

  my $match_root;
  if ($host =~ /^www\./) {
    my $_host = substr $host, 4;
    if (first_index { $_ eq $_host } @altnames) {
      $match_root = 'yes';
    } else {
      $match_root = 'no';
    }
  } else {
    $match_root = 'Not for subdomains';
  }

  return {
    alt_names  => \@altnames,
    issuer     => $issuer,
    key_algo   => $key_alg,
    match_cn   => $match_cn,
    match_top  => $match_root,
    subject    => $subject,
    not_before => $not_before,
    not_after  => $not_after,
    sign_algo  => $sign_alg,
  };
}

sub check_server {
  my ($host, $refresh) = @_;

  my $force = $refresh || 0;

  if (!-e "./jsons/${host}.json" || $force) {
    my $agent = $useragents[rand @useragents];
    system('./external/whatweb/whatweb', '-q', '-a=3', "-U='${agent}'", "--log-json=./jsons/${host}.json", $host);
    open FHT, '<', "./jsons/${host}.json" or die $!;
    if (scalar @{[<FHT>]} == 0) {
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

sub merge_ciphers {
  my ($merged) = @_;

  my @output;
  my @pfs;
  my $pfs = 0;
  my $cipher = '';

  foreach (@$merged) {
    $cipher = $_->{'cipher'};
    if (!grep {$_ eq $cipher} @output) {
      push @output, $cipher;
      if ($_->{'pfs'} eq 'pfs') {
        $pfs += 1;
        push @pfs, $_->{'cipher'};
      }
    }
  }

  return (\@output, $pfs, \@pfs);
}

sub get_ciphers {
  my ($data) = @_;

  my @sslv3  = $data->{'SSLv3'}  || ();
  my @tlsv1  = $data->{'TLSv1'}  || ();
  my @tlsv11 = $data->{'TLSv11'} || ();
  my @tlsv12 = $data->{'TLSv12'} || ();

  my $merged = zip(@sslv3, @tlsv1, @tlsv11, @tlsv12);

  return merge_ciphers($merged);
}

sub count_pfs {
  my ($data) = @_;
  my $pfs = 0;
  while(my ($key, $value) = each(%$data)) {
    $pfs += 1 if ($value eq 'pfs');
  }
  return $pfs
}
