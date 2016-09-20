#
# INCLUDES
#
import OTXv2

# Local network functions
import libs.network

# STDERR
import sys

#
# CLASSES
#

class OTX(object):
    """
    Class to hold OTX items.
    """
    def __init__(self, PublicAPI):
        self.PublicAPI = PublicAPI
        self.otx = OTXv2.OTXv2(PublicAPI)
        self.ipv4url = ('https://otx.alienvault.com'
                        '/api/v1/indicators/IPv4/{}/{}')
        self.domainurl = ('https://otx.alienvault.com/'
                          'api/v1/indicators/domain/{}/{}')
        self.hostnameurl = ('https://otx.alienvault.com/'
                            'api/v1/indicators/hostname/{}/{}')

    """
    Adds appropriate headers to input list.
    """
    def add_headers(self, inputheaders):
        inputheaders.append('OTX URL')
        inputheaders.append('OTX General Postal Code')
        inputheaders.append('OTX General Country Code')
        inputheaders.append('OTX General City')
        inputheaders.append('OTX General Whois')
        inputheaders.append('OTX General DMA Code')
        inputheaders.append('OTX General Country Name')
        inputheaders.append('OTX General Area Code')
        inputheaders.append('OTX General Continent Code')
        inputheaders.append('OTX General Latitude')
        inputheaders.append('OTX General Longitude')
        inputheaders.append('OTX General ASN')
        inputheaders.append('OTX General Country Code 3')
        inputheaders.append('OTX Reputation AS')
        inputheaders.append('OTX Reputation Threat Score')
        inputheaders.append('OTX Reputation First Seen')
        inputheaders.append('OTX Reputation Tags')
        inputheaders.append('OTX Reputation Last Seen')
        inputheaders.append('OTX Reputation Org')
        inputheaders.append('OTX Reputation Country')

    """
    Adds the pulled data to the input row.
    """
    def add_row(self, host, inputrow):
        if libs.network.IsIPv4(host):
            try:
                otxgendata = self.otx.get(self.ipv4url.format(host, 'general'))
                otxrepdata = self.otx.get(self.ipv4url.format(host,
                                          'reputation')).get('reputation', {})
                if otxrepdata is None:
                    otxrepdata = {}
                otxurl = ('https://otx.alienvault.com/'
                          'indicator/ip/{}'.format(host))
            except OTXv2.InvalidAPIKey:
                sys.stderr.write("ERROR:  OTX API key invalid!\n")
                raise
            except OTXv2.BadRequest:
                otxgendata = {}
                otxrepdata = {}
                otxurl = "Invalid IP"
            except AttributeError:
                otxgendata = {}
                otxrepdata = {}
                otxurl = "OTX DID NOT RETURN INFO, TRY THIS HOST AGAIN!"
        elif libs.network.IsDomain(host):
            try:
                otxgendata = self.otx.get(self.domainurl.format(host,
                                          'general'))
                otxrepdata = self.otx.get(self.domainurl.format(host,
                                          'reputation')).get('reputation', {})
                if otxrepdata is None:
                    otxrepdata = {}
                otxurl = ('https://otx.alienvault.com/'
                          'indicator/domain/{}'.format(host))
            except OTXv2.InvalidAPIKey:
                sys.stderr.write("ERROR:  OTX API key invalid!\n")
                raise
            except OTXv2.BadRequest:
                otxgendata = {}
                otxrepdata = {}
                otxurl = "Invalid Domain"
            except AttributeError:
                otxgendata = {}
                otxrepdata = {}
                otxurl = "OTX DID NOT RETURN INFO, TRY THIS HOST AGAIN!"
        else:
            try:
                otxgendata = self.otx.get(self.hostnameurl.format(host,
                                          'general'))
                otxrepdata = self.otx.get(self.hostnameurl.format(host,
                                          'reputation')).get('reputation', {})
                if otxrepdata is None:
                    otxrepdata = {}
                otxurl = ('https://otx.alienvault.com/'
                          'indicator/hostname/{}'.format(host))
            except OTXv2.InvalidAPIKey:
                sys.stderr.write("ERROR:  OTX API key invalid!\n")
                raise
            except OTXv2.BadRequest:
                otxgendata = {}
                otxrepdata = {}
                otxurl = "Invalid FQDN"
            except AttributeError:
                otxgendata = {}
                otxrepdata = {}
                otxurl = "OTX DID NOT RETURN INFO, TRY THIS HOST AGAIN!"

        # General fields
        otxgenpostalcode = otxgendata.get('postal_code', '')
        otxgencountrycode = otxgendata.get('country_code', '')
        otxgencity = otxgendata.get('city', '')
        otxgenwhois = otxgendata.get('whois', '')
        otxgendmacode = otxgendata.get('dma_code', '')
        otxgencountryname = otxgendata.get('country_name', '')
        otxgenareacode = otxgendata.get('area_code', '')
        otxgencontinentcode = otxgendata.get('continent_code', '')
        otxgenlat = otxgendata.get('latitude', '')
        otxgenlong = otxgendata.get('longitude', '')
        otxgenasn = otxgendata.get('asn', '')
        otxgencountrycode3 = otxgendata.get('country_code3', '')

        # Reputation fields
        otxrepas = otxrepdata.get('as', '')
        otxrepthreatscore = otxrepdata.get('threat_score', '')
        otxrepfirstseen = otxrepdata.get('first_seen', '')
        otxreptags = '; '.join(otxrepdata.get('counts', {}).keys())
        otxreplastseen = otxrepdata.get('last_seen', '')
        otxreporg = otxrepdata.get('organization', '')
        otxrepcountry = otxrepdata.get('country', '')

        inputrow.append(otxurl)
        inputrow.append(otxgenpostalcode)
        inputrow.append(otxgencountrycode)
        inputrow.append(otxgencity)
        inputrow.append(otxgenwhois)
        inputrow.append(otxgendmacode)
        inputrow.append(otxgencountryname)
        inputrow.append(otxgenareacode)
        inputrow.append(otxgencontinentcode)
        inputrow.append(otxgenlat)
        inputrow.append(otxgenlong)
        inputrow.append(otxgenasn)
        inputrow.append(otxgencountrycode3)
        inputrow.append(otxrepas)
        inputrow.append(otxrepthreatscore)
        inputrow.append(otxrepfirstseen)
        inputrow.append(otxreptags)
        inputrow.append(otxreplastseen)
        inputrow.append(otxreporg)
        inputrow.append(otxrepcountry)
