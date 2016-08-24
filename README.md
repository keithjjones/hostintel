# hostintel

This tool is used to collect various intelligence sources for hosts.
Hosts are identified by FQDN host name, Domain, or IP address.
This tool only supports IPv4 at the moment.
The output is in CSV format and sent to STDOUT
so the data can be saved or piped into another program.
Since the output is in CSV format, spreadsheets such as Excel or database systems will
easily be able to import the data.

```
$ python hostintel.py -h
usage: hostintel.py [-h] [-a] [-d] [-v] [-p] [-s] [-t] [-n]
                    ConfigurationFile InputFile

Look up host intelligence information. Outputs CSV to STDOUT.

positional arguments:
  ConfigurationFile   Configuration file
  InputFile           Input file, one host per line (IP, domain, or FQDN host
                      name)

optional arguments:
  -h, --help          show this help message and exit
  -a, --all           Perform All Lookups.
  -d, --dns           DNS Lookup.
  -v, --virustotal    VirusTotal Lookup.
  -p, --passivetotal  PassiveTotal Lookup. (WORK IN PROGRESS)
  -s, --shodan        Shodan Lookup. (WORK IN PROGRESS)
  -t, --threatgroup   ThreatGroup Lookup. (WORK IN PROGRESS)
  -n, --neutrino      NeutrinoAPI Lookup. (WORK IN PROGRESS)
```

# Install:
First, make sure your configuration file is correct for your computer/installation.
Add your API keys and usernames as appropriate in the configuration file.
Next, install the python requirements:

```
$ pip install -r requirements.txt
```

# Intelligence Sources:

  - GeoLite2 (No network I/O required)
    - http://www.maxmind.com
  - DNS (Network I/O required)
    - https://github.com/rthalley/dnspython
  - VirusTotal (Private API key and network I/O required, throttled when appropriate)
    - http://www.virustotal.com
  - Shodan (API key and network I/O required) (WORK IN PROGRESS)
    - http://www.shodan.io
  - PassiveTotal (API key, username, and network I/O required) (WORK IN PROGRESS)
    - http://www.passivetotal.com
  - ThreatCrowd (Network I/O required) (WORK IN PROGRESS)
    - http://www.threatcrowd.org
  - NeutrinoAPI (API key and network I/O required) (WORK IN PROGRESS)
    - http://www.neutrinoapi.com

# Resources:

   - The GeoIP2 Python library - https://github.com/maxmind/GeoIP2-python
   - The Python DNS library - https://github.com/rthalley/dnspython
   - Foundation of DNS lookups inspired by http://www.iodigitalsec.com/performing-dns-queries-python/
   - The VirusTotal Python library - https://github.com/blacktop/virustotal-api
   - The Shodan Python library - http://shodan.readthedocs.io/en/latest/ and https://github.com/achillean/shodan-python
   - The PassiveTotal Python library - https://passivetotal.readthedocs.io/en/latest/ and https://github.com/passivetotal/python_api
   - The ThreatCrowd Python library - https://github.com/threatcrowd/ApiV2 and https://github.com/jheise/threatcrowd_api

# License
This application is covered by the Creative Commons BY-SA license.

```
This product includes GeoLite2 data created by MaxMind, available from
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.
```
   



