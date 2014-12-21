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
