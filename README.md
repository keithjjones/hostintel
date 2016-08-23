# hostintel

This tool is used to collect various intelligence sources for hosts.
Hosts are identified by FQDN host name, Domain, or IP address.

```
$python hostintel.py -h
usage: hostintel.py [-h] [-a] [-d] [-v] [-n] ConfigurationFile InputFile

Look up host intelligence information. Outputs CSV to STDOUT.

positional arguments:
  ConfigurationFile  Configuration file
  InputFile          Input file, one host per line (IP, domain, or FQDN host
                     name)

optional arguments:
  -h, --help         show this help message and exit
  -a, --all          Perform All Lookups.
  -d, --dns          DNS Lookup.
  -v, --virustotal   VirusTotal Lookup.
  -n, --neutrino     NeutrinoAPI Lookup.
```

# Install:
First, make sure your configuration file is correct for your computer/installation.
Next, install the python requirements:

```
$ pip install -r requirements.txt
```

# Intelligence Sources:

  - GeoLite2 (No network I/O required)
  - DNS (Network I/O required)
  - VirusTotal (Private API key and network I/O required)
  - NeutrinoAPI (API key and network I/O required)

# Resources:

   - The GeoIP2 Python library - https://github.com/maxmind/GeoIP2-python
   - Foundation of DNS lookups inspired by http://www.iodigitalsec.com/performing-dns-queries-python/

# License
This application is covered by the Creative Commons BY-SA license.

```
This product includes GeoLite2 data created by MaxMind, available from
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.
```
   



