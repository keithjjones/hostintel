#
# INCLUDES
#
import threatcrowd

# Need sleep function
import time
# Need local network functions
import libs.network

#
# CLASSES
#

class ThreatCrowd(object):
    """
    Class to hold ThreatCrowd items.
    """
    def __init__(self):
        pass
    
    """
    Adds appropriate headers to input list.
    """
    def add_headers(self,inputheaders):
        inputheaders.append('ThreatCrowd URL')
        inputheaders.append('ThreatCrowd Votes')
        inputheaders.append('ThreatCrowd References')
        inputheaders.append('ThreatCrowd Number of Hashes')
        inputheaders.append('ThreatCrowd Number of Resolutions')
        inputheaders.append('ThreatCrowd Number of Subdomains')
        inputheaders.append('ThreatCrowd Emails')

    """
    Adds the pulled data to the input row.
    """    
    def add_row(self,host,inputrow):
        time.sleep(10)  # Time speficied in API documents to be nice.

        IsValid = False

        # TC sometimes has a bad SSL handshake, this should fix it
        while IsValid == False:
            try:
                if libs.network.IsIPv4(host):            
                    tcdata = threatcrowd.ip_report(host)
                else:
                    tcdata = threatcrowd.domain_report(host)
                IsValid = True
            except:
                IsValid = False
        
        tcurl = tcdata.get('permalink','https://www.threatcrowd.org/ip.php?ip={}'.format(host))
        
        tcresolutions = tcdata.get('resolutions',[])
        tcresolutionslist = []
        for resolution in tcresolutions:
            if resolution.has_key('domain'):
                tcresolutionslist.append(resolution.get('domain',''))
            elif resolution.has_key('ip_address'):
                tcresolutionslist.append(resolution.get('ip_address',''))
        tcresolutionsout = len(tcresolutionslist)

        tcvotes = tcdata.get('votes','')

        tcreferences = '\n'.join(tcdata.get('references',[]))

        tchashes = len(tcdata.get('hashes',[]))

        tcsubdomains = len(tcdata.get('subdomains',[]))

        tcemails = '\n'.join(tcdata.get('emails',[]))
        
        inputrow.append(tcurl)
        inputrow.append(tcvotes)
        inputrow.append(tcreferences)
        inputrow.append(tchashes)
        inputrow.append(tcresolutionsout)
        inputrow.append(tcsubdomains)
        inputrow.append(tcemails)
