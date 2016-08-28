#
# INCLUDES
#

# For the sleep function
import time

import censys.ipv4

import sys

# Local network functions
import libs.network

#
# CLASSES
#

class Censys(object):
    """
    Class to hold Censys items.
    """
    def __init__(self,PublicAPI,Secret):
        self.PublicAPI = PublicAPI
        self.Secret = Secret
        self.NeedConnection = True

        while self.NeedConnection:            
            try:
                self.censysipv4 = censys.ipv4.CensysIPv4(PublicAPI,Secret)
                self.NeedConnection = False
            except censys.base.CensysRateLimitExceededException:
                self.NeedConnection = True
                time.sleep(60)
            except:
                sys.stderr.write('ERROR: Censys API Credential Issue!\n')
                raise
            
    
    """
    Adds appropriate headers to input list.
    """
    def add_headers(self,inputheaders):
        inputheaders.append('Censys IPv4 Tags')
        inputheaders.append('Censys IPv4 Updated At')
        inputheaders.append('Censys IPv4 City')
        inputheaders.append('Censys IPv4 Province')
        inputheaders.append('Censys IPv4 Country')
        inputheaders.append('Censys IPv4 Country Code')
        inputheaders.append('Censys IPv4 Longitude')
        inputheaders.append('Censys IPv4 Latitude')
        inputheaders.append('Censys IPv4 Registered Country')
        inputheaders.append('Censys IPv4 Registered Country Code')
        inputheaders.append('Censys IPv4 Postal Code')
        inputheaders.append('Censys IPv4 Time Zone')
        inputheaders.append('Censys IPv4 Continent')
        inputheaders.append('Censys IPv4 ASN Org')
        inputheaders.append('Censys IPv4 ASN Description')
        inputheaders.append('Censys IPv4 ASN RIR')
        inputheaders.append('Censys IPv4 ASN Routed Prefix')
        inputheaders.append('Censys IPv4 ASN Country Code')
        inputheaders.append('Censys IPv4 ASN Path')
        inputheaders.append('Censys IPv4 ASN ASN')
        inputheaders.append('Censys IPv4 ASN Name')
        inputheaders.append('Censys IPv4 Protocols')
        inputheaders.append('Censys Matching Endpoints')
        inputheaders.append('Censys URL')

    """
    Adds the pulled data to the input row.
    """    
    def add_row(self,host,inputrow):
        if libs.network.IsIPv4(host):
            try:
                censysipv4data = self.censysipv4.view(host)
            except censys.base.CensysNotFoundException as e:
                censysipv4data = {}
            censysurl = 'https://censys.io/ipv4/{}'.format(host)
        else:
            censysipv4query = self.censysipv4.search(host)
            censysurl = 'https://censys.io/ipv4?q={}'.format(host)
            censysipv4data = {}

        censysipv4tags = '; '.join(censysipv4data.get('tags',''))
        censysipv4updatedat = censysipv4data.get('updated_at','')

        censysipv4location = censysipv4data.get('location',{})

        censysipv4province = censysipv4location.get('province','')
        censysipv4city = censysipv4location.get('city','')
        censysipv4country = censysipv4location.get('country','')
        censysipv4long = censysipv4location.get('longitude','')
        censysipv4lat = censysipv4location.get('latitude','')
        censysipv4regcountry = censysipv4location.get('registered_country','')
        censysipv4regcountrycode = censysipv4location.get('registered_country_code','')
        censysipv4postalcode = censysipv4location.get('postal_code','')
        censysipv4countrycode = censysipv4location.get('country_code','')
        censysipv4timezone = censysipv4location.get('timezone','')
        censysipv4continent = censysipv4location.get('continent','')

        censysipv4as = censysipv4data.get('autonomous_system',{})

        censysipv4asdesc = censysipv4as.get('description','')
        censysipv4asrir = censysipv4as.get('rir','')
        censysipv4asroutedprefix = censysipv4as.get('routed_prefix','')
        censysipv4ascountrycode = censysipv4as.get('country_code','')
        censysipv4aspath = censysipv4as.get('path','')
        censysipv4asorg = censysipv4as.get('organization','')
        censysipv4asasn = censysipv4as.get('asn','')
        censysipv4asname = censysipv4as.get('name','')

        censysipv4protocols = '; '.join(censysipv4data.get('protocols',[]))

        inputrow.append(censysipv4tags)
        inputrow.append(censysipv4updatedat)
        inputrow.append(censysipv4city)
        inputrow.append(censysipv4province)
        inputrow.append(censysipv4country)
        inputrow.append(censysipv4countrycode)
        inputrow.append(censysipv4long)
        inputrow.append(censysipv4lat)
        inputrow.append(censysipv4regcountry)
        inputrow.append(censysipv4regcountrycode)
        inputrow.append(censysipv4postalcode)
        inputrow.append(censysipv4timezone)
        inputrow.append(censysipv4continent)
        inputrow.append(censysipv4asorg)
        inputrow.append(censysipv4asdesc)
        inputrow.append(censysipv4asrir)
        inputrow.append(censysipv4asroutedprefix)
        inputrow.append(censysipv4ascountrycode)
        inputrow.append(censysipv4aspath)
        inputrow.append(censysipv4asasn)
        inputrow.append(censysipv4asname)
        inputrow.append(censysipv4protocols)

        # Too slow
        #censysmatchingaddresses = []
        #for result in censysipv4query:
        #    censysmatchingaddresses.append(result['ip'])   
        #inputrow.append(str(len(censysmatchingaddresses)))

        try:
            censysipv4query
            try:
                censysipv4query.next()
                inputrow.append(str(True))
            except:
                inputrow.append(str(False))            
        except:
            inputrow.append('')
            
        
        inputrow.append(censysurl)
