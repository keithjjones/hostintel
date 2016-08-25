#
# INCLUDES
#
import passivetotal.libs.enrichment
import passivetotal.libs.whois

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

    """
    Adds the pulled data to the input row.
    """    
    def add_row(self,host,inputrow):
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
