# Main Application

#
# INCLUDES
#

# Required for complex command line argument parsing.
import argparse
# Required for configuration files
import ConfigParser
# Required for GeoIP2 lookups
import geoip2.database
# Required for CSV
import csv
# Required for STDOUT
import sys
# Required for DNS lookups
import dns.resolver
# Required for regular expressions
import re
# Required for VirusTotal API
from virus_total_apis import PublicApi as VirusTotalPublicApi
# Required for sleep function
import time

#
# FUNCTIONS
#

# Function to determine if host is an IPv4 address
def IsIPv4(host):
    if re.match('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',host):
        return True
    else:
        return False

# Function to determine if host is a domain (only one period in host)
def IsDomain(host):
    if re.match('[^\.]*\.[^\.]*',host):
        return True
    else:
        return False

# Function to determine if host is a FQDN host name
def IsFQDN(host):
    if IsIPv4(host) or IsDomain(host):
        return False
    else:
        return True

# Function to create reverse lookup address, inspired by:
# http://www.iodigitalsec.com/performing-dns-queries-python/
def ReverseAddress(IP):
    RevIP = '.'.join(reversed(IP.split('.'))) + '.in-addr.arpa'
    return RevIP

# Function to DNS lookup host
def DNSLookupHost(host):
    try:
        if IsIPv4(host):
            return dns.resolver.query(ReverseAddress(host),'PTR')
        else:
            return dns.resolver.query(host,'A')
    except:
        return []
    

#
# COMMAND LINE ARGS
#

# Setup command line argument parsing.
parser = argparse.ArgumentParser(
    description='Look up host intelligence information. Outputs CSV to STDOUT.')
parser.add_argument('ConfigurationFile', help='Configuration file')
parser.add_argument('InputFile',
                    help='Input file, one host per line (IP, domain, or FQDN host name)')
parser.add_argument('-a','--all', action='store_true', help='Perform All Lookups.')
parser.add_argument('-d','--dns',  action='store_true', help='DNS Lookup.')
parser.add_argument('-v','--virustotal', action='store_true', help='VirusTotal Lookup.')
parser.add_argument('-n','--neutrino', action='store_true', help='NeutrinoAPI Lookup.')

#
# MAIN PROGRAM
#

# Parse command line arguments.
args = parser.parse_args()

# Parse Configuration File
ConfigFile = ConfigParser.ConfigParser()
ConfigFile.read(args.ConfigurationFile)

# Pull GeoIP2 City Database Path
try:
    geoip2citydb = ConfigFile.get('GeoIP2','City_Path')
except:
    print "ERROR:  GeoIP2 City Database Config File Error!"
    exit(1)
    
# Open file and read into list named hosts
try:
    with open(args.InputFile) as infile:
        hosts = infile.read().splitlines()
except:
    print "ERROR: Cannot open InputFile!"
    exit(1)
    
# Open the GEOIP2 database
try:
    geo = geoip2.database.Reader(geoip2citydb)
except:
    print geoip2citydb
    print "ERROR: Cannot open GEOIP2 City Database!"
    exit(1)
    
# Setup CSV to STDOUT
output = csv.writer(sys.stdout)

# Print the header to STDOUT
output.writerow(['Input Host','IPv4','FQDN','Country','Postal','City','State','Lat','Long','VirusTotal Detected URLs','VirusTotal Detected Communicating Samples','VirusTotal Detected Downloaded Samples','VirusTotal URL']);

# Iterate through all of the input hosts
for host in hosts:
    # Clear variables
    ipv4 = fqdn = \
    geodata = geocountry = \
    geopostal = geocity = geosubdivision = \
    geolat = geolong = \
    vtdetectedurls = \
    vtdetectedcommunicatingsamples = \
    vtdetecteddownloadedsamples = \
    vturl = ''
    
    # Pull the GeoIP2 information...
    if IsIPv4(host):
        ipv4=host
    else:
        fqdn = host
        
    try:
        geodata = geo.city(host)
        geocountry = geodata.country.name
        geopostal = geodata.postal.code
        geocity = geodata.city.name
        geosubdivision = geodata.subdivisions.most_specific.name
        geolat = geodata.location.latitude
        geolong = geodata.location.longitude
    except:
        pass

    # Pull the DNS information...
    if args.dns or args.all:
        if IsIPv4(host):
            fqdn = '; '.join(map(str,DNSLookupHost(host)))
        else:
            ipv4 = '; '.join(map(str,DNSLookupHost(host)))

    # Pull the VirusTotal information
    if args.virustotal or args.all:
        vtapi = ConfigFile.get('VirusTotal','PublicAPI')
        vt = VirusTotalPublicApi(vtapi)
        if IsIPv4(host):
            vtresponse = vt.get_ip_report(host)
            while vtresponse["response_code"] != 200 and vtresponse["response_code"] != 403:
                time.sleep(60)  # Sleep for the API throttling
                vtresponse = vt.get_ip_report(host)
            if not vtresponse.has_key("results"):
                vtdetectedurls = "INVALID API KEY"            
            elif vtresponse["results"].has_key("detected_urls"):
                vtdetectedurls = str(len(vtresponse["results"]["detected_urls"]))
            else:
                vtdetectedurls = str(0)
            if not vtresponse.has_key("results"):
                vtdetectedcommunicatingsamples = "INVALID API KEY"
            elif vtresponse["results"].has_key("detected_communicating_samples"):
                vtdetectedcommunicatingsamples = str(len(vtresponse["results"]["detected_communicating_samples"]))
            else:
                vtdetectedcommunicatingsamples = str(0)
            vturl = "https://www.virustotal.com/en/ip-address/{}/information/".format(host)
        else:
            vtresponse = vt.get_domain_report(host)
            while vtresponse["response_code"] != 200 and vtresponse["response_code"] != 403:
                time.sleep(60)  # Sleep for the API throttling
                vtresponse = vt.get_domain_report(host)
            if not vtresponse.has_key("results"):
                vtdetectedurls = "INVALID API KEY"
            elif vtresponse["results"].has_key("detected_urls"):
                vtdetectedurls = str(len(vtresponse["results"]["detected_urls"]))
            else:
                vtdetectedurls = str(0)
            if not vtresponse.has_key("results"):
                vtdetectedcommunicatingsamples = "INVALID API KEY"
            elif vtresponse["results"].has_key("detected_communicating_samples"):
                vtdetectedcommunicatingsamples = str(len(vtresponse["results"]["detected_communicating_samples"]))
            else:
                vtdetectedcommunicatingsamples = str(0)
            if not vtresponse.has_key("results"):
                vtdetecteddownloadedsamples = "INVALID API KEY"
            elif vtresponse["results"].has_key("detected_downloaded_samples"):
                vtdetecteddownloadedsamples = str(len(vtresponse["results"]["detected_downloaded_samples"]))
            else:
                vtdetecteddownloadedsamples = str(0)
            vturl = "https://www.virustotal.com/en/domain/{}/information/".format(host)
                
    # Print the output line
    output.writerow([host,ipv4,fqdn,geocountry,geopostal,geocity,geosubdivision,geolat,geolong,vtdetectedurls,vtdetectedcommunicatingsamples,vtdetecteddownloadedsamples,vturl])

# Close the GEOIP2 database
geo.close()

# Exit without error
exit(0)
    

