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
        
        whoiscontactemail = whoisdata.get('contactEmail', '')

        whoiswhoisserver = whoisdata.get('whoisServer', '')

        whoisregistryupdated = whoisdata.get('registryUpdatedAt', '')

        if 'admin' in whoisdata and 'organization' in whoisdata['admin']:
            whoisadminorg = whoisdata['admin'].get('organization', '')
        else:
            whoisadminorg = ''

        if 'tech' in whoisdata and 'organization' in whoisdata['tech']:
            whoistechorg = whoisdata['tech']['organization']
        else:
            whoistechorg = ''

        if 'registrant' in whoisdata and 'organization' in whoisdata['registrant']:
            whoisregistrantorg = whoisdata['registrant']['organization']
        else:
            whoisregistrantorg = ''

        if 'registrant' in whoisdata and 'name' in whoisdata['registrant']:
            whoisregistrantname = whoisdata['registrant']['name']
        else:
            whoisregistrantname = ''

        if 'registrant' in whoisdata and 'country' in whoisdata['registrant']:
            whoisregistrantcountry = whoisdata['registrant']['country']
        else:
            whoisregistrantcountry = ''

        whoisregistrar = whoisdata.get('registrar', '')

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

        enrichmentnetwork = enrichmentdata.get('network', '')

        if 'tags' in enrichmentdata:
            enrichmenttags = '; '.join(enrichmentdata['tags'])
        else:
            enrichmenttags = ''

        enrichmentcountry = enrichmentdata.get('country', '')

        enrichmentlong = enrichmentdata.get('longitude', '')

        enrichmentlat = enrichmentdata.get('latitude', '')

        enrichmentsinkhole = enrichmentdata.get('sinkhole', '')

        enrichmentasn = enrichmentdata.get('autonomousSystemNumber', '')

        enrichmentasnname = enrichmentdata.get('autonomousSystemName', '')

        enrichmentevercompromised = enrichmentdata.get('everCompromised', '')

        enrichmentprimarydomain = enrichmentdata.get('primaryDomain', '')

        enrichmentdynamicdns = enrichmentdata.get('dynamicDns', '')

        if 'subdomains' in enrichmentdata:
            enrichmentsubdomains = '; '.join(enrichmentdata['subdomains'])
        else:
            enrichmentsubdomains = ''

        enrichmenttld = enrichmentdata.get('tld', '')

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

        if 'results' in malwaredata:
            malwarestring = len(malwaredata['results'])
        else:
            malwarestring = 'INVALID CREDENTIALS'

        inputrow.append(malwarestring)

        # OSInt data
        
        osintdata = self.ptenrichment.get_osint(query=host)

        if 'results' in osintdata:
            osintstring = len(osintdata['results'])
        else:
            osintstring = 'INVALID CREDENTIALS'

        inputrow.append(osintstring)
