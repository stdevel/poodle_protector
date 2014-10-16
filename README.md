poodle_protector
================

``poodle_protector.py`` is a Python script for automatically protecting your systems against POODLE vulnerability ([*CVE-2014-3566*](http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-3566)).
It scans your Apache server configuration directories for unsecure configuration directives and ensures security by disabling SSL 2.0 and 3.0. It can also restart your server instantly after customizing the configuration.

This only works for Linux web servers using Apache.



Parameters
==========
```
# ./poodle_protector.py -h
Usage: poodle_protector.py [options]

poodle_protector.py is used to protect your servers against POODLE
vulnerability (CVE-2014-3566). It automatically detects apache configuration
files vulnerable to POODLE and customizes them after creating backups.
Checkout the GitHub page for updates:
https://github.com/stdevel/poodle_protector

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -c STRING, --custom-string=STRING
                        defines a custom SSLProtocol configuration string
  -p PATH, --custom-path=PATH
                        defines a custom path for apache configuration files
                        in case you're not using distribution defaults
  -q, --quiet           don't print status messages to stdout
  -d, --debug           enable debugging outputs
  -n, --no-backup       don't create backups if you like to like dangerously
  -l, --dry-run         only simulates what would be done
  -r, --service-reload  reloads the affected service using the 'service'
                        wrapper
```



Examples
========
Just do a dry-run to see what the script would do:
```
# ./poodle_protector.py -l
I'd like to create a backup of '/etc/apache2/mods-available/ssl.conf as '/etc/apache2/mods-available/ssl.conf.20141016-1303' ...
I'd like to insert 'SSLProtocol All -SSLv3 -SSLv3' into /etc/apache2/mods-available/ssl.conf using the following command: sed -i '/SSLProtocol/ c\SSLProtocol All -SSLv2 -SSLv3' /etc/apache2/mods-available/ssl.conf ...
I'd also like to restart the service using: ['service httpd restart', 'service apache2 restart']
```

Ensure security by customizing the configuration and reload the service (*Debian machine, that's why the httpd directories and service can't be found*):
```
# ./poodle_protector.py -r
httpd: unrecognized service
Restarting web server: apache2 ... waiting .
```
