use strict;
use warnings;
use utf8;

use LWP::UserAgent;

sub find_trackers {
  my ($host) = @_;


  my @useragents = (
    'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0',
    'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0',
    'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0',
    'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)',
  );

  my $agent = $useragents[rand @useragents];
  my $ua = LWP::UserAgent->new();
  $ua->timeout(5);
  $ua->agent($agent);

  my $req = HTTP::Request->new('GET',"http://${host}/");
  my $res = $ua->request($req);
  my $content = $res->content;

  my @result;

  push @result, 'Google Analystics' if (google_analytics($content));
  push @result, 'Piwik'             if (piwik($content));
  push @result, 'StatCount'         if (statcounter($content));
  push @result, 'OneStat'           if (onestat($content));
  push @result, 'XiTi'              if (xiti($content));

  return \@result;
}

sub google_analytics {
  my ($content) = @_;
  return ($content =~ /_gaq.push\(\['_setAccount'/i || $content =~ /ga\([\s]*'create'/i) || 0;
}

sub piwik {
  my ($content) = @_;
  return ($content =~ /piwik\.(js|php)/i) || 0;
}

sub statcounter {
  my ($content) = @_;
  return ($content =~ /statcounter/i) || 0;
}

sub onestat {
  my ($content) = @_;
  return ($content =~ /stat\.onestat\.com/i || $content =~ /OneStat/) || 0;
}

sub xiti {
  my ($content) = @_;
  return ($content =~ /xiti-logo-noscript/i || $content =~ /logi3?\.xiti\.com/i) || 0;
}

1;
