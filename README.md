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

## Checks
* default cipher negociated with the server
* accepted protocols (SSLv3, TLS1, TLS11 and TLS12)
* accepted cipher strings per protocol
* IP information (IP addresses and RIPE informations)
* certificate issuer
* certificate subject
* certificate altName
* certificate validity dates

## Side notes
This script was first a test in order to check some Swiss e-banking connection.
It's not perfect, and there might be better way to do those tests. Its output is
just an indication.

For now, it doesn't test for known CVE like POODLE, Heartbleed and so on.

## Contribution
Feel free to fork this project and do some pull-request if you find errors or
some new tests it might do.
