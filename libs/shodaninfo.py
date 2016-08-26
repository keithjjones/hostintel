#
# INCLUDES
#

# Shodan API library
import shodan

# Local network functions
import libs.network

#
# CLASSES
#

class Shodan(object):
    """
    Class to hold Shodan items.
    """
    def __init__(self, publicapi):
        self.publicapi = publicapi
        self.shodan = shodan.Shodan(publicapi)
    
    """
    Adds appropriate headers to input list.
    """
    def add_headers(self,inputheaders):
        inputheaders.append('Shodan Org')
        inputheaders.append('Shodan ISP')
        inputheaders.append('Shodan Hostnames')
        inputheaders.append('Shodan ASN')
        inputheaders.append('Shodan Ports')
        inputheaders.append('Shodan City')
        inputheaders.append('Shodan Region Code')
        inputheaders.append('Shodan Postal Code')
        inputheaders.append('Shodan Country Name')
        inputheaders.append('Shodan Country Code')
        inputheaders.append('Shodan Country Code 3')
        inputheaders.append('Shodan Tags')
        inputheaders.append('Shodan Area Code')
        inputheaders.append('Shodan DMA Code')
        inputheaders.append('Shodan Last Update')
        inputheaders.append('Shodan Latitude')
        inputheaders.append('Shodan Longitude')
        inputheaders.append('Shodan Total Hits')
        inputheaders.append('Shodan URL')

    """
    Adds the pulled data to the input row.
    """    
    def add_row(self,host,inputrow):
        
        if libs.network.IsIPv4(host):
            try:
                shodandata = self.shodan.host(host)
                shodanurl = "https://www.shodan.io/host/{}".format(host)
            except shodan.exception.APIError as e:
                shodandata = {}
                shodanurl = '{}'.format(e.value)
        else:
            try:
                shodandata = self.shodan.search(host)
                shodanurl = "https://www.shodan.io/search?query={}".format(host)
            except shodan.exception.APIError as e:
                shodandata = {}
                shodanurl = '{}'.format(e.value)

        shodancity = shodandata.get('city','')
        shodanregion = shodandata.get('region_code','')
        shodantags = '; '.join(shodandata.get('tags',''))
        shodanisp = shodandata.get('isp','')
        shodanareacode = shodandata.get('area_code','')
        shodandmacode = shodandata.get('dma_code','')
        shodanlastupdate = shodandata.get('last_update','')
        shodancountrycode3 = shodandata.get('country_code3','')
        shodanlatitude = shodandata.get('latitude','')
        shodanlongitude = shodandata.get('longitude','')
        shodanhostnames = '; '.join(shodandata.get('hostnames',''))
        shodanpostalcode = shodandata.get('postal_code','')
        shodancountrycode = shodandata.get('country_code','')
        shodanorg = shodandata.get('org','')
        shodancountryname = shodandata.get('country_name','')
        shodanasn = shodandata.get('asn','')
        shodanports = '; '.join(map(str,shodandata.get('ports','')))
        shodantotalhits = str(shodandata.get('total',''))

        inputrow.append(shodanorg)
        inputrow.append(shodanisp)
        inputrow.append(shodanhostnames)
        inputrow.append(shodanasn)
        inputrow.append(shodanports)
        inputrow.append(shodancity)
        inputrow.append(shodanregion)
        inputrow.append(shodanpostalcode)
        inputrow.append(shodancountryname)
        inputrow.append(shodancountrycode)
        inputrow.append(shodancountrycode3)
        inputrow.append(shodantags)
        inputrow.append(shodanareacode)
        inputrow.append(shodandmacode)
        inputrow.append(shodanlastupdate)
        inputrow.append(shodanlatitude)
        inputrow.append(shodanlongitude)
        inputrow.append(shodantotalhits)
        inputrow.append(shodanurl)
