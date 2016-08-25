#
# NOTE:  There are many more items this API will provide, these are the most useful
#

#
# INCLUDES
#
import passivetotal.libs.whois
import passivetotal.libs.enrichment

#
# CLASSES
#

class PT(object):
    """
    Class to hold PassiveTotal items.
    """
    def __init__(self, ptusername, ptpublicapi):
        self.ptusername = ptusername
        self.ptpublicapi = ptpublicapi
        self.ptenrichment = passivetotal.libs.enrichment.EnrichmentRequest(ptusername,ptpublicapi)
        self.ptwhois = passivetotal.libs.whois.WhoisRequest(ptusername,ptpublicapi)

    """
    Adds appropriate headers to input list.
    """
    def add_headers(self,inputheaders):
        inputheaders.append('PassiveTotal Whois Contact Email')
        inputheaders.append('PassiveTotal Whois Server')
        inputheaders.append('PassiveTotal Whois Updated')
        inputheaders.append('PassiveTotal Whois Admin Organization')
        inputheaders.append('PassiveTotal Whois Tech Organization')
        inputheaders.append('PassiveTotal Whois Registrant Organization')
        inputheaders.append('PassiveTotal Whois Registrant Name')
        inputheaders.append('PassiveTotal Whois Country')
        inputheaders.append('PassiveTotal Whois Registrar')
        inputheaders.append('PassiveTotal Enrichment Network')
        inputheaders.append('PassiveTotal Enrichment Tags')
        inputheaders.append('PassiveTotal Enrichment Country')
        inputheaders.append('PassiveTotal Enrichment Longitude')
        inputheaders.append('PassiveTotal Enrichment Latitude')
        inputheaders.append('PassiveTotal Enrichment Sinkhole')
        inputheaders.append('PassiveTotal Enrichment ASN')
        inputheaders.append('PassiveTotal Enrichment ASN Name')
        inputheaders.append('PassiveTotal Enrichment Ever Compromised')
        inputheaders.append('PassiveTotal Enrichment Primary Domain')
        inputheaders.append('PassiveTotal Enrichment Dynamic DNS')
        inputheaders.append('PassiveTotal Enrichment Sub Domains')
        inputheaders.append('PassiveTotal Enrichment Top Level Domain')
        inputheaders.append('PassiveTotal Malware Samples')
        inputheaders.append('PassiveTotal OSInt Samples')
        

    """
    Adds the pulled data to the input row.
    """    
    def add_row(self,host,inputrow):
        
        # Whois data
        
        whoisdata = self.ptwhois.get_whois_details(query=host)
        
        if whoisdata.has_key('contactEmail'):
            whoiscontactemail = whoisdata['contactEmail']
        else:
            whoiscontactemail = ''

        if whoisdata.has_key('whoisServer'):
            whoiswhoisserver = whoisdata['whoisServer']
        else:
            whoiswhoisserver = ''

        if whoisdata.has_key('registryUpdatedAt'):
            whoisregistryupdated = whoisdata['registryUpdatedAt']
        else:
            whoisregistryupdated = ''

        if whoisdata.has_key('admin') and whoisdata['admin'].has_key('organization'):
            whoisadminorg = whoisdata['admin']['organization']
        else:
            whoisadminorg = ''

        if whoisdata.has_key('tech') and whoisdata['tech'].has_key('organization'):
            whoistechorg = whoisdata['tech']['organization']
        else:
            whoistechorg = ''

        if whoisdata.has_key('registrant') and whoisdata['registrant'].has_key('organization'):
            whoisregistrantorg = whoisdata['registrant']['organization']
        else:
            whoisregistrantorg = ''

        if whoisdata.has_key('registrant') and whoisdata['registrant'].has_key('name'):
            whoisregistrantname = whoisdata['registrant']['name']
        else:
            whoisregistrantname = ''

        if whoisdata.has_key('registrant') and whoisdata['registrant'].has_key('country'):
            whoisregistrantcountry = whoisdata['registrant']['country']
        else:
            whoisregistrantcountry = ''

        if whoisdata.has_key('registrar'):
            whoisregistrar = whoisdata['registrar']
        else:
            whoisregistrar = ''

        inputrow.append(whoiscontactemail)
        inputrow.append(whoiswhoisserver)
        inputrow.append(whoisregistryupdated)
        inputrow.append(whoisadminorg)
        inputrow.append(whoistechorg)
        inputrow.append(whoisregistrantorg)
        inputrow.append(whoisregistrantname)
        inputrow.append(whoisregistrantcountry)
        inputrow.append(whoisregistrar)

        # Enrichment data
        
        enrichmentdata = self.ptenrichment.get_enrichment(query=host)

        if enrichmentdata.has_key('network'):
            enrichmentnetwork = enrichmentdata['network']
        else:
            enrichmentnetwork = ''

        if enrichmentdata.has_key('tags'):
            enrichmenttags = '; '.join(enrichmentdata['tags'])
        else:
            enrichmenttags = ''

        if enrichmentdata.has_key('country'):
            enrichmentcountry = enrichmentdata['country']
        else:
            enrichmentcountry = ''

        if enrichmentdata.has_key('longitude'):
            enrichmentlong = enrichmentdata['longitude']
        else:
            enrichmentlong = ''

        if enrichmentdata.has_key('latitude'):
            enrichmentlat = enrichmentdata['latitude']
        else:
            enrichmentlat = ''

        if enrichmentdata.has_key('sinkhole'):
            enrichmentsinkhole = enrichmentdata['sinkhole']
        else:
            enrichmentsinkhole = ''

        if enrichmentdata.has_key('autonomousSystemNumber'):
            enrichmentasn = enrichmentdata['autonomousSystemNumber']
        else:
            enrichmentasn = ''

        if enrichmentdata.has_key('autonomousSystemName'):
            enrichmentasnname = enrichmentdata['autonomousSystemName']
        else:
            enrichmentasnname = ''

        if enrichmentdata.has_key('everCompromised'):
            enrichmentevercompromised = enrichmentdata['everCompromised']
        else:
            enrichmentevercompromised = ''

        if enrichmentdata.has_key('primaryDomain'):
            enrichmentprimarydomain = enrichmentdata['primaryDomain']
        else:
            enrichmentprimarydomain = ''

        if enrichmentdata.has_key('dynamicDns'):
            enrichmentdynamicdns = enrichmentdata['dynamicDns']
        else:
            enrichmentdynamicdns = ''

        if enrichmentdata.has_key('subdomains'):
            enrichmentsubdomains = '; '.join(enrichmentdata['subdomains'])
        else:
            enrichmentsubdomains = ''

        if enrichmentdata.has_key('tld'):
            enrichmenttld = enrichmentdata['tld']
        else:
            enrichmenttld = ''

        inputrow.append(enrichmentnetwork)
        inputrow.append(enrichmenttags)
        inputrow.append(enrichmentcountry)
        inputrow.append(enrichmentlong)
        inputrow.append(enrichmentlat)
        inputrow.append(enrichmentsinkhole)
        inputrow.append(enrichmentasn)
        inputrow.append(enrichmentasnname)
        inputrow.append(enrichmentevercompromised)
        inputrow.append(enrichmentprimarydomain)
        inputrow.append(enrichmentdynamicdns)
        inputrow.append(enrichmentsubdomains)
        inputrow.append(enrichmenttld)

        # Malware data
        
        malwaredata = self.ptenrichment.get_malware(query=host)

        if malwaredata.has_key('results'):
            malwarestring = len(malwaredata['results'])
        else:
            malwarestring = 'INVALID CREDENTIALS'

        inputrow.append(malwarestring)

        # OSInt data
        
        osintdata = self.ptenrichment.get_osint(query=host)

        if osintdata.has_key('results'):
            osintstring = len(osintdata['results'])
        else:
            osintstring = 'INVALID CREDENTIALS'

        inputrow.append(osintstring)
