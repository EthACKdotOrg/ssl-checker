# SSL Checker

Simple perl script allowing to know a bit more about
SSL connection offered by a service.

## Check SSL capabilities
It will list secure protocoles and give a hint about accepted
ciphers. It also will do some checks regarding the certificate and
provide information about hosting.

## Usage
Create a file named "urls". It might be a CSV with two columns:
* main host name
* a subdomain

The script will then loop on the file content and run a serie of checks.
It will then create a JSON file with the whole output. You might follow the
script run with live output.

## Features
* output as a JSON (hash, index is the URL)
* link frontend to subdomain
* oriented for ebanking checks first, but might be use for any other websites
* update an existing JSON (add new entries)

## Checks
* default cipher negociated with the server
* accepted protocols (SSLv3, TLS1, TLS11 and TLS12)
* accepted cipher strings per protocol
* IP information (IP addresses and RIPE information)
* certificate issuer
* certificate subject
* certificate altName
* certificate validity dates
* certificate algorithm
* server headers (CSP, HSTS, X-Frame)
* server version (when available)
* heartbleed status

## Side notes
This script was first a test in order to check some Swiss e-banking connection.
It's not perfect, and there might be better way to do those tests. Its output is
just an indication.

## Dependencies
* [Data::Dumper](http://search.cpan.org/~smueller/Data-Dumper-2.154/Dumper.pm)
* [IO::Socket::IP](http://search.cpan.org/~pevans/IO-Socket-IP-0.34/lib/IO/Socket/IP.pm)
* [IO::Socket::SSL](http://search.cpan.org/~sullr/IO-Socket-SSL-2.008/lib/IO/Socket/SSL.pod)
* [JSON](http://search.cpan.org/~makamaka/JSON-2.90/lib/JSON.pm)
* [List::MoreUtils](http://search.cpan.org/~rehsack/List-MoreUtils-0.401/lib/List/MoreUtils.pm)
* [LWP::UserAgent](http://search.cpan.org/~mschilli/libwww-perl-6.08/lib/LWP/UserAgent.pm)
* [Net::DNS](http://search.cpan.org/~nlnetlabs/Net-DNS-0.81/lib/Net/DNS.pm)
* [Net::SSLeay](http://search.cpan.org/~mikem/Net-SSLeay-1.66/lib/Net/SSLeay.pod)
* [Net::Whois::IP](http://search.cpan.org/~bschmitz/Net-Whois-IP-1.15/IP.pm)
* [Perl::Version](http://search.cpan.org/~bdfoy/Perl-Version-1.013/lib/Perl/Version.pm)
* [Term::ANSIColor](http://search.cpan.org/~rra/Term-ANSIColor-4.03/lib/Term/ANSIColor.pm)
* [Text::CSV](http://search.cpan.org/~makamaka/Text-CSV-1.32/lib/Text/CSV.pm)
* [Time::ParseDate](http://search.cpan.org/~muir/Time-ParseDate-2013.1113/lib/Time/ParseDate.pm)


## Contribution
Feel free to fork this project and do some pull-request if you find errors or
some new tests it might do.
