# SSL Checker

Simple perl script allowing to know a bit more about
SSL connection offered by a service.

## Check SSL capabilities
It will list secure protocoles and give a hint about accepted
ciphers. It also will do some checks regarding the certificate and
provide information about hosting.

## Usage
Create a file named "urls". It might be a CSV with three columns:
* entity name
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

## Side notes
This script was first a test in order to check some Swiss e-banking connection.
It's not perfect, and there might be better way to do those tests. Its output is
just an indication.

## Dependencies
* XML::Simple
* XML::XML2JSON


## Contribution
Feel free to fork this project and do some pull-request if you find errors or
some new tests it might do.
