# hostintel

This tool is used to collect various intelligence sources for hosts.
Hostintel is written in a modular fashion so new intelligence sources can be
easily added.

Hosts are identified by FQDN host name, Domain, or IP address.  This
tool only supports IPv4 at the moment.  The output is in CSV format
and sent to STDOUT so the data can be saved or piped into another
program.  Since the output is in CSV format, spreadsheets such as
Excel or database systems will easily be able to import the data.

I created a short introduction for this tool on YouTube: https://youtu.be/aYK0gILDA6w

This works with Python v2, but it should also work with Python v3.  If you find it does not work
with Python v3 please post an issue.

## Help Screen:

```
$ python hostintel.py -h
usage: hostintel.py [-h] [-a] [-d] [-v] [-p] [-s] [-c] [-t] [-o] [-i] [-r]
                    ConfigurationFile InputFile

Modular application to look up host intelligence information. Outputs CSV to
STDOUT. This application will not output information until it has finished all
of the input.

positional arguments:
  ConfigurationFile     Configuration file
  InputFile             Input file, one host per line (IP, domain, or FQDN
                        host name)

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             Perform All Lookups.
  -d, --dns             DNS Lookup.
  -v, --virustotal      VirusTotal Lookup.
  -p, --passivetotal    PassiveTotal Lookup.
  -s, --shodan          Shodan Lookup.
  -c, --censys          Censys Lookup.
  -t, --threatcrowd     ThreatCrowd Lookup.
  -o, --otx             OTX by AlienVault Lookup.
  -i, --isc             Internet Storm Center DShield Lookup.
  -r, --carriagereturn  Use carriage returns with new lines on csv.
```

# Install:

First, make sure your configuration file is correct for your
computer/installation.  Add your API keys and usernames as appropriate
in the configuration file.  Python and Pip are required to run this
tool.  There are modules that must be installed from GitHub, so be
sure the git command is available from your command line.  Git is easy
to install for any platform.  Next, install the python requirements
(run this each time you git pull this repository too):

```
$ pip install -r requirements.txt
```

There have been some problems with the stock version of Python on Mac
OSX
(http://stackoverflow.com/questions/31649390/python-requests-ssl-handshake-failure).
You may have to install the security portion of the requests library
with the following command:

```
$ pip install requests[security]
```

Lastly, I am a fan of virtualenv for Python.  To make a customized local installation of
Python to run this tool, I recommend you read:  http://docs.python-guide.org/en/latest/dev/virtualenvs/

# Running:

```
$ python hostintel.py myconfigfile.conf myhosts.txt -a > myoutput.csv
```
You should be able to import myoutput.csv into any database or spreadsheet program.

**Note that depending on your network, your API key limits, and the data you are searching for,
this script can run for a very long time!  Use each module sparingly!  In return for the long
wait, you save yourself from having to pull this data manually.**

## Sample Data:

There is some sample data in the "sampledata" directory.  The IPs, domains, and hosts
were picked at random and by no means is meant to target any organization or individual.
Running this tool on the sample data works in the following way:

### Small Hosts List:
```
$ python hostintel.py local/config.conf sampledata/smalllist.txt -a > sampledata/smalllist.csv
*** Processing 8.8.8.8 ***
*** Processing 8.8.4.4 ***
*** Processing 192.168.1.1 ***
*** Processing 10.0.0.1 ***
*** Processing google.com ***
*** Processing 212.227.247.242 ***
*** Writing Output ***
```

### Larger Hosts List:
```
$ python hostintel.py local/config.conf sampledata/largerlist.txt -a > sampledata/largerlist.csv
*** Processing 114.34.84.13 ***
*** Processing 116.102.34.212 ***
*** Processing 118.75.180.168 ***
*** Processing 123.195.184.13 ***
*** Processing 14.110.216.236 ***
*** Processing 14.173.147.69 ***
*** Processing 14.181.192.151 ***
*** Processing 146.120.11.66 ***
*** Processing 163.172.149.131 ***

...

*** Processing 54.239.26.180 ***
*** Processing 62.141.39.155 ***
*** Processing 71.6.135.131 ***
*** Processing 72.30.2.74 ***
*** Processing 74.125.34.101 ***
*** Processing 83.31.179.71 ***
*** Processing 85.25.217.155 ***
*** Processing 93.174.93.94 ***
*** Writing Output ***
```

# Intelligence Sources:

You can get API keys at the sites below for your configuration file.

  - GeoLite2 (No network I/O required)
    - http://www.maxmind.com
  - DNS (Network I/O required)
    - https://github.com/rthalley/dnspython
  - VirusTotal (Public API key and network I/O required, throttled when appropriate)
    - http://www.virustotal.com
  - PassiveTotal (API key, username, and network I/O required)
    - http://www.passivetotal.com
  - Shodan (API key and network I/O required)
    - http://www.shodan.io
  - Censys (API key, username, and network I/O required)
    - http://www.censys.io
  - ThreatCrowd (Network I/O required, throttled when appropriate)
    - http://www.threatcrowd.org
  - OTX by AlienVault (API key and network I/O required)
    - https://otx.alienvault.com
  - Internet Storm Center (Network I/O required)
    - https://isc.sans.edu

# Resources:

   - The GeoIP2 Python library
     - https://github.com/maxmind/GeoIP2-python
   - The Python DNS library
     - https://github.com/rthalley/dnspython
     - Foundation of DNS lookups inspired by http://www.iodigitalsec.com/performing-dns-queries-python/
   - The VirusTotal Python library
     - https://github.com/blacktop/virustotal-api
   - The Shodan Python library
     - http://shodan.readthedocs.io/en/latest/
     - https://github.com/achillean/shodan-python
   - The Censys Python library
     - https://github.com/censys/censys-python
     - https://www.censys.io/api
   - The PassiveTotal Python library
     - https://passivetotal.readthedocs.io/en/latest/
     - https://github.com/passivetotal/python_api
   - The ThreatCrowd Python library
     - https://github.com/threatcrowd/ApiV2
     - https://github.com/jheise/threatcrowd_api
   - The OTX Python Library
     - https://github.com/AlienVault-Labs/OTX-Python-SDK
     - https://otx.alienvault.com/api/
   - The Internet Storm Center DShield Python Library
     - https://github.com/rshipp/python-dshield
     - https://isc.sans.edu/api/

# Notes:

Crude notes are available [here](notes/Notes.png).

# License:

This application is covered by the Creative Commons BY-SA license.

- https://creativecommons.org/licenses/by-sa/4.0/
- https://creativecommons.org/licenses/by-sa/4.0/legalcode

```
This product includes GeoLite2 data created by MaxMind, available from
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.
```

# Contributing:

Read [Contributing.md] (Contributing.md)

# To Do:

 - Try to incorporate https://github.com/mlsecproject/combine
 - Try to incorporate threat feeds from http://www.secrepo.com/
 - Add Malwr
 - Add column to display if input was IPv4, domain, or hostname
 - Look at https://github.com/Yelp/threat_intel
