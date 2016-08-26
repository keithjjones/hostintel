# hostintel

This tool is used to collect various intelligence sources for hosts.
Hostintel is written in a modular fashion so new intelligence sources can be
easily added.
Hosts are identified by FQDN host name, Domain, or IP address.
This tool only supports IPv4 at the moment.
The output is in CSV format and sent to STDOUT
so the data can be saved or piped into another program.
Since the output is in CSV format, spreadsheets such as Excel or database systems will
easily be able to import the data.

```
$ python hostintel.py -h
usage: hostintel.py [-h] [-a] [-d] [-v] [-p] [-s] [-c] [-t] [-n]
                    ConfigurationFile InputFile

Modular application to look up host intelligence information. Outputs CSV to
STDOUT. This application will not output information until it has finished all
of the input.

positional arguments:
  ConfigurationFile   Configuration file
  InputFile           Input file, one host per line (IP, domain, or FQDN host
                      name)

optional arguments:
  -h, --help          show this help message and exit
  -a, --all           Perform All Lookups.
  -d, --dns           DNS Lookup.
  -v, --virustotal    VirusTotal Lookup.
  -p, --passivetotal  PassiveTotal Lookup.
  -s, --shodan        Shodan Lookup.
  -c, --censys        Censys Lookup.
  -t, --threatcrowd   ThreatCrowd Lookup.
```

# Install:
First, make sure your configuration file is correct for your computer/installation.
Add your API keys and usernames as appropriate in the configuration file.
Next, install the python requirements:

```
$ pip install -r requirements.txt
```

There have been some problems with the stock version of Python on Mac OSX (http://stackoverflow.com/questions/31649390/python-requests-ssl-handshake-failure).  You may have to
install the security portion of the requests library with the following command:

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
this script can run for a very long time!  Use each module sparingly!  In return for the long wait, you save yourself from having to pull this data manually.**

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

# Resources:

   - The GeoIP2 Python library - https://github.com/maxmind/GeoIP2-python
   - The Python DNS library - https://github.com/rthalley/dnspython
     - Foundation of DNS lookups inspired by http://www.iodigitalsec.com/performing-dns-queries-python/
   - The VirusTotal Python library - https://github.com/blacktop/virustotal-api
   - The Shodan Python library - http://shodan.readthedocs.io/en/latest/ and https://github.com/achillean/shodan-python
   - The Censys Python library - https://github.com/censys/censys-python and https://www.censys.io/api
   - The PassiveTotal Python library - https://passivetotal.readthedocs.io/en/latest/ and https://github.com/passivetotal/python_api
   - The ThreatCrowd Python library - https://github.com/threatcrowd/ApiV2 and https://github.com/jheise/threatcrowd_api

# License
This application is covered by the Creative Commons BY-SA license.

- https://creativecommons.org/licenses/by-sa/4.0/
- https://creativecommons.org/licenses/by-sa/4.0/legalcode

```
This product includes GeoLite2 data created by MaxMind, available from
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.
```

# Contributing

Read Contributing.md
   



