#
# INCLUDES
#
import dshield

#
# CLASSES
#

class ISC(object):
    """
    Class to hold ISC DShield items.
    """
    def __init__(self):
        pass
    
    """
    Adds appropriate headers to input list.
    """
    def add_headers(self,inputheaders):
        inputheaders.append('ISC URL')
        inputheaders.append('ISC Count')
        inputheaders.append('ISC Comment')
        inputheaders.append('ISC Updated')
        inputheaders.append('ISC Threat Feeds')
        inputheaders.append('ISC Network')
        inputheaders.append('ISC Attacks')
        inputheaders.append('ISC Min Date')
        inputheaders.append('ISC Max Date')
        inputheaders.append('ISC Number')
        inputheaders.append('ISC Max Risk')
        inputheaders.append('ISC AS')
        inputheaders.append('ISC AS Name')
        inputheaders.append('ISC AS Size')
        inputheaders.append('ISC AS Country')
        inputheaders.append('ISC AS Abuse Contact')
        inputheaders.append('ISC Alexa Domains')
        inputheaders.append('ISC Alexa Last Rank')
        inputheaders.append('ISC Alexa Host Name')
        inputheaders.append('ISC Alexa First Seen')
        inputheaders.append('ISC Alexa Last Seen')

    """
    Adds the pulled data to the input row.
    """    
    def add_row(self,host,inputrow):
        try:
            iscdata = dshield.ip(host)['ip']
            iscurl = 'https://isc.sans.edu/ipinfo.html?ip={}'.format(host)
        except dshield.Error:
            iscdata = {}
            iscurl = "Bad IP"

        isccount = iscdata.get('count','')
        isccomment = iscdata.get('comment','')
        iscupdated = iscdata.get('updated','')
        iscthreatfeeds = '; '.join(iscdata.get('threatfeeds',{}).keys())
        iscnetwork = iscdata.get('network','')
        iscattacks = iscdata.get('attacks','')
        iscmaxdate = iscdata.get('maxdate','')
        iscascountry = iscdata.get('ascountry','')
        iscnumber = iscdata.get('number','')
        iscassize = iscdata.get('assize','')
        iscmaxrisk = iscdata.get('maxrisk','')
        iscas = iscdata.get('as','')
        iscasabusecontact = iscdata.get('asabusecontact','')
        iscasname = iscdata.get('asname','')

        iscdataalexa = iscdata.get('alexa',{})
        
        iscalexadomains = iscdataalexa.get('domains','')
        iscalexalastrank = iscdataalexa.get('lastrank','')
        iscalexahostname = iscdataalexa.get('hostname','')
        iscalexalastseen = iscdataalexa.get('lastseen','')
        iscalexafirstseen = iscdataalexa.get('firstseen','')
        
        iscmindate = iscdata.get('mindate','')

        inputrow.append(iscurl)
        inputrow.append(isccount)
        inputrow.append(isccomment)
        inputrow.append(iscupdated)
        inputrow.append(iscthreatfeeds)
        inputrow.append(iscnetwork)
        inputrow.append(iscattacks)
        inputrow.append(iscmindate)
        inputrow.append(iscmaxdate)
        inputrow.append(iscnumber)
        inputrow.append(iscmaxrisk)
        inputrow.append(iscas)
        inputrow.append(iscasname)
        inputrow.append(iscassize)
        inputrow.append(iscascountry)
        inputrow.append(iscasabusecontact)
        inputrow.append(iscalexadomains)
        inputrow.append(iscalexalastrank)
        inputrow.append(iscalexahostname)
        inputrow.append(iscalexafirstseen)
        inputrow.append(iscalexalastseen)
