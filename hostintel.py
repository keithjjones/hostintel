# Main Application

#
# INCLUDES
#

# Local network functions
import libs.network
# Local GeoIP functions
import libs.geoip
# Local DNS functions
import libs.dnsinfo
# Required for complex command line argument parsing.
import argparse
# Required for configuration files
import ConfigParser
# Required for CSV
import csv
# Required for STDOUT
import sys
# Required for VirusTotal API
from virus_total_apis import PublicApi as VirusTotalPublicApi
# Required for sleep function
import time

#
# FUNCTIONS
#
    

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
parser.add_argument('-p','--passivetotal', action='store_true', help='PassiveTotal Lookup. (WORK IN PROGRESS)')
parser.add_argument('-s','--shodan', action='store_true', help='Shodan Lookup. (WORK IN PROGRESS)')
parser.add_argument('-t','--threatgroup', action='store_true', help='ThreatGroup Lookup. (WORK IN PROGRESS)')
parser.add_argument('-n','--neutrino', action='store_true', help='NeutrinoAPI Lookup. (WORK IN PROGRESS)')

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

# Pull GeoIP2 City Database Path
geoip2citydb = ConfigFile.get('GeoIP2','City_Path')

# Setup GeoIP object
try:    
    GeoIP = libs.geoip.GeoIP(geoip2citydb)
except:
    print("ERROR:  Cannot open GeoIP Database!")
    exit(1)
    
# Open file and read into list named hosts
try:
    with open(args.InputFile) as infile:
        hosts = infile.read().splitlines()
except:
    print("ERROR: Cannot open InputFile!")
    exit(1)
    
# Setup CSV to STDOUT
output = csv.writer(sys.stdout)

# Add standard header info
Headers.append('Input Host')

# Iterate through all of the input hosts
for host in hosts:
    # Clear the row
    row = []
    
    # Add the host to the output
    row.append(host)

    # Lookup DNS
    if args.dns or args.all:
        DNSInfo = libs.dnsinfo.DNSInfo()
        DNSInfo.add_headers(Headers)
        DNSInfo.add_row(host,row)
    
    # Lookup GeoIP
    GeoIP.add_headers(Headers)
    GeoIP.add_row(host,row)
        
    # Add the row to the output data set
    Data.append(row)

#     # Pull the VirusTotal information
#     if args.virustotal or args.all:
#         vtapi = ConfigFile.get('VirusTotal','PublicAPI')
#         vt = VirusTotalPublicApi(vtapi)
#         if libs.network.IsIPv4(host):
#             vtresponse = vt.get_ip_report(host)
#             while vtresponse["response_code"] != 200 and vtresponse["response_code"] != 403:
#                 time.sleep(60)  # Sleep for the API throttling
#                 vtresponse = vt.get_ip_report(host)
#             if not vtresponse.has_key("results"):
#                 vtdetectedurls = "INVALID API KEY"            
#             elif vtresponse["results"].has_key("detected_urls"):
#                 vtdetectedurls = str(len(vtresponse["results"]["detected_urls"]))
#             else:
#                 vtdetectedurls = str(0)
#             if not vtresponse.has_key("results"):
#                 vtdetectedcommunicatingsamples = "INVALID API KEY"
#             elif vtresponse["results"].has_key("detected_communicating_samples"):
#                 vtdetectedcommunicatingsamples = str(len(vtresponse["results"]["detected_communicating_samples"]))
#             else:
#                 vtdetectedcommunicatingsamples = str(0)
#             vturl = "https://www.virustotal.com/en/ip-address/{}/information/".format(host)
#         else:
#             vtresponse = vt.get_domain_report(host)
#             while vtresponse["response_code"] != 200 and vtresponse["response_code"] != 403:
#                 time.sleep(60)  # Sleep for the API throttling
#                 vtresponse = vt.get_domain_report(host)
#             if not vtresponse.has_key("results"):
#                 vtdetectedurls = "INVALID API KEY"
#             elif vtresponse["results"].has_key("detected_urls"):
#                 vtdetectedurls = str(len(vtresponse["results"]["detected_urls"]))
#             else:
#                 vtdetectedurls = str(0)
#             if not vtresponse.has_key("results"):
#                 vtdetectedcommunicatingsamples = "INVALID API KEY"
#             elif vtresponse["results"].has_key("detected_communicating_samples"):
#                 vtdetectedcommunicatingsamples = str(len(vtresponse["results"]["detected_communicating_samples"]))
#             else:
#                 vtdetectedcommunicatingsamples = str(0)
#             if not vtresponse.has_key("results"):
#                 vtdetecteddownloadedsamples = "INVALID API KEY"
#             elif vtresponse["results"].has_key("detected_downloaded_samples"):
#                 vtdetecteddownloadedsamples = str(len(vtresponse["results"]["detected_downloaded_samples"]))
#             else:
#                 vtdetecteddownloadedsamples = str(0)
#             vturl = "https://www.virustotal.com/en/domain/{}/information/".format(host)

#     if args.passivetotal or args.all:
#         ptuser = ConfigFile.get('PassiveTotal','Username')
#         ptapi = ConfigFile.get('PassiveTotal','PublicAPI')
#         print ptuser
#         print ptapi
    
# Write the header
output.writerow(Headers)

# Write each row
for row in Data:
    output.writerow(row)

# Exit without error
exit(0)
    

