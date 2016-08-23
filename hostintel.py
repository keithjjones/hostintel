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
import dns

#
# COMMAND LINE ARGS
#

# Setup command line argument parsing.
parser = argparse.ArgumentParser(
    description='Look up host intelligence information. Outputs CSV to STDOUT.')
parser.add_argument('ConfigurationFile', help='Configuration file')
parser.add_argument('InputFile',
                    help='Input file, one host per line (IP, domain, or FQDN host name)')
parser.add_argument('-a', action='store_true', help='Perform All Lookups.')
parser.add_argument('-v', action='store_true', help='VirusTotal Lookup.')
parser.add_argument('-n', action='store_true', help='NeutrinoAPI Lookup.')

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
    print "ERROR: Cannot open GEOIP2 City Database!"
    exit(1)
    
# Setup CSV to STDOUT
output = csv.writer(sys.stdout)

# Print the header to STDOUT
output.writerow(['Input Host','Country','Postal','City','State','Lat','Long']);

# Iterate through all of the input hosts
for host in hosts:
    # Pull the GeoIP2 information...
    try:
        geodata = geo.city(host)
        geocountry = geodata.country.name
        geopostal = geodata.postal.code
        geocity = geodata.city.name
        geosubdivision = geodata.subdivisions.most_specific.name
        geolat = geodata.location.latitude
        geolong = geodata.location.longitude
    except:
        geodata = geocountry = geopostal = geocity = geosubdivision = geolat = geolong = ''

    # Print the output line
    output.writerow([host,geocountry,geopostal,geocity,geosubdivision,geolat,geolong])

# Close the GEOIP2 database
geo.close()
    

