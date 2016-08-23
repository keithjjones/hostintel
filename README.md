# hostintel

This tool is used to collect various intelligence sources for hosts.
Hosts are identified by FQDN host name, domain, or IP address.

```
$ python hostintel.py -h
usage: hostintel.py [-h] [-a] [-v] [-n] InputFile

Look up host intelligence information.

positional arguments:
  InputFile   Input file, one host per line (IP, domain, or FQDN host name)

optional arguments:
  -h, --help  show this help message and exit
  -a          Perform All Lookups.
  -v          VirusTotal Lookup.
  -n          NeutrinoAPI Lookup.
```

## Intelligence Sources:

   - VirusTotal (Private API key required)
   - NeutrinoAPI (API key required)
   - GeoLite2 (No network I/O required)

## Resources:

   - The GeoIP2 Python library - https://github.com/maxmind/GeoIP2-python

```
This product includes GeoLite2 data created by MaxMind, available from
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.
```
   



