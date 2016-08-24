#
# INCLUDES
#

# Required for GeoIP2 lookups
import geoip2.database

#
# CLASSES
#
class GeoIP(object):
    """
    Class to hold GeoIP items.
    """
    
    #
    # FUNCTIONS
    #
    """
    Setup GeoIP DB path and opens database.  Exception if it cannot open database.
    """
    def __init__(self,databasepath):
        self.dbpath = databasepath
        # Open the GEOIP2 database, exception if cannot
        self.geoip = geoip2.database.Reader(self.dbpath)

    """
    Adds appropriate headers to input list.
    """
    def add_headers(self,inputlist):
        inputlist.append('Country')
        inputlist.append('Postal')
        inputlist.append('City')
        inputlist.append('State')
        inputlist.append('Lat')
        inputlist.append('Long')

    """
    Adds the pulled data to the input row.
    """
    def add_row(self, host, inputrow):
        try:
            geodata = self.geoip.city(host)
            inputrow.append(geodata.country.name)
            inputrow.append(geodata.postal.code)
            inputrow.append(geodata.city.name)
            inputrow.append(geodata.subdivisions.most_specific.name)
            inputrow.append(geodata.location.latitude)
            inputrow.append(geodata.location.longitude)
        except:
            inputrow.append('')
            inputrow.append('')
            inputrow.append('')
            inputrow.append('')
            inputrow.append('')
            inputrow.append('')
