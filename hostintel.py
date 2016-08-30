# Main Application

#
# INCLUDES
#

# Local network functions
import libs.network
# Required for complex command line argument parsing.
import argparse
# Required for configuration files
import ConfigParser
# Required for CSV
import csv
# Required for STDOUT
import sys

# MODULES:  Add additional intelligence source modules here

# Local GeoIP functions
import libs.geoip
# Local DNS functions
import libs.dnsinfo
# Local VirusTotal functions
import libs.vt
# Local PassiveTotal functions
import libs.pt
# Local Shodan functions
import libs.shodaninfo
# Local Censys functions
import libs.censysinfo
# Local ThreatCrowd functions
import libs.threatcrowdinfo
# Local OTX functions
import libs.otx
# Local ISC DShield functions
import libs.isc

#
# COMMAND LINE ARGS
#

# Setup command line argument parsing.
parser = argparse.ArgumentParser(
    description='Modular application to look up host intelligence information. Outputs CSV to STDOUT.')
parser.add_argument('ConfigurationFile', help='Configuration file')
parser.add_argument('InputFile',
                    help='Input file, one host per line (IP, domain, or FQDN host name)')
parser.add_argument('-a','--all', action='store_true', help='Perform All Lookups.')
parser.add_argument('-d','--dns',  action='store_true', help='DNS Lookup.')
parser.add_argument('-v','--virustotal', action='store_true', help='VirusTotal Lookup.')
parser.add_argument('-p','--passivetotal', action='store_true', help='PassiveTotal Lookup.')
parser.add_argument('-s','--shodan', action='store_true', help='Shodan Lookup.')
parser.add_argument('-c','--censys', action='store_true', help='Censys Lookup.')
parser.add_argument('-t','--threatcrowd', action='store_true', help='ThreatCrowd Lookup.')
parser.add_argument('-o','--otx', action='store_true', help='OTX by AlienVault Lookup.')
parser.add_argument('-i','--isc', action='store_true', help='Internet Storm Center DShield Lookup.')
parser.add_argument('-r','--carriagereturn', action='store_true', help='Use carriage returns with new lines on csv.')

#
# MAIN PROGRAM
#

# Parse command line arguments.
args = parser.parse_args()

# Parse Configuration File
ConfigFile = ConfigParser.ConfigParser()
ConfigFile.read(args.ConfigurationFile)

# Setup the headers list
Headers = []

# Setup the data list
Data = []

# MODULES:  Setup additional intelligence source modules here

# Pull GeoIP2 City Database Path
geoip2citydb = ConfigFile.get('GeoIP2','City_Path')

# Setup GeoIP object
try:    
    GeoIP = libs.geoip.GeoIP(geoip2citydb)
except:
    sys.stderr.write("ERROR:  Cannot open GeoIP Database!\n")
    exit(1)

# Pull the VirusTotal config
vtpublicapi = ConfigFile.get('VirusTotal','PublicAPI')

# Pull the PassiveTotal config
ptusername = ConfigFile.get('PassiveTotal','Username')
ptpublicapi = ConfigFile.get('PassiveTotal','PublicAPI')

# Pull the Shodan config
shodanpublicapi = ConfigFile.get('Shodan','PublicAPI')

# Pull the Censys config
censyssecret = ConfigFile.get('Censys','Secret')
censyspublicapi = ConfigFile.get('Censys','PublicAPI')

# Pull the OTX config
otxpublicapi = ConfigFile.get('OTX','PublicAPI')

# Open file and read into list named hosts
try:
    with open(args.InputFile) as infile:
        hosts = infile.read().splitlines()
except:
    sys.stderr.write("ERROR:  Cannot open InputFile!\n")
    exit(1)
    
# Setup CSV to STDOUT
if args.carriagereturn:
    output = csv.writer(sys.stdout, lineterminator='\r\n')
else:
    output = csv.writer(sys.stdout, lineterminator='\n')

# Add standard header info
Headers.append('Input Host')

# Print Header Flag
PrintHeaders = True

# Abort Flag
Aborted = False

# Iterate through all of the input hosts
for host in hosts:
    try:
        # Output status
        sys.stderr.write('*** Processing {} ***\n'.format(host))

        # Clear the row
        row = []

        # Add the host to the output
        row.append(host)

        # Lookup DNS
        if args.dns or args.all:
            DNSInfo = libs.dnsinfo.DNSInfo()
            if PrintHeaders:
                DNSInfo.add_headers(Headers)
            DNSInfo.add_row(host,row)

        # Lookup GeoIP
        if PrintHeaders:
            GeoIP.add_headers(Headers)
        GeoIP.add_row(host,row)

        # Lookup VirusTotal
        if args.virustotal or args.all:
            VT = libs.vt.VT(vtpublicapi)
            if PrintHeaders:
                VT.add_headers(Headers)
            VT.add_row(host,row)

        # Lookup PassiveTotal
        if args.passivetotal or args.all:
            PT = libs.pt.PT(ptusername,ptpublicapi)
            if PrintHeaders:
                PT.add_headers(Headers)
            PT.add_row(host,row)

        # Lookup Shodan
        if args.shodan or args.all:
            Shodan = libs.shodaninfo.Shodan(shodanpublicapi)
            if PrintHeaders:
                Shodan.add_headers(Headers)
            Shodan.add_row(host,row)

        # Lookup Censys
        if args.censys or args.all:
            Censys = libs.censysinfo.Censys(censyspublicapi,censyssecret)
            if PrintHeaders:
                Censys.add_headers(Headers)
            Censys.add_row(host,row)

        # Lookup ThreatCrowd
        if args.threatcrowd or args.all:
            ThreatCrowd = libs.threatcrowdinfo.ThreatCrowd()
            if PrintHeaders:
                ThreatCrowd.add_headers(Headers)
            ThreatCrowd.add_row(host,row)

        # Lookup OTX
        if args.otx or args.all:
            OTX = libs.otx.OTX(otxpublicapi)
            if PrintHeaders:
                OTX.add_headers(Headers)
            OTX.add_row(host,row)

        # Lookup ISC DShield
        if args.isc or args.all:
            ISC = libs.isc.ISC()
            if PrintHeaders:
                ISC.add_headers(Headers)
            ISC.add_row(host,row)

        # MODULES:  Add additional intelligence source modules here

        # Add the row to the output data set
        Data.append(row)

        # Print out the headers
        if PrintHeaders:
            output.writerow(Headers)

        # Print out the data
        output.writerow([unicode(field).encode('utf-8') for field in row])
        
        # This turns off headers for remaining rows
        PrintHeaders = False
    except:
        # There was an error...
        sys.stderr.write('ERROR:  An exception was raised!  Raising original exception for debugging.\n')
        raise
        
# Exit without error
exit(0)
    

