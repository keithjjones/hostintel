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
        inputheaders.append('ThreatCrowd Hashes')
        inputheaders.append('ThreatCrowd Resolutions')
        inputheaders.append('ThreatCrowd Subdomains')
        inputheaders.append('ThreatCrowd Emails')

    """
    Adds the pulled data to the input row.
    """    
    def add_row(self,host,inputrow):
        time.sleep(10)  # Time speficied in API documents to be nice.

        if libs.network.IsIPv4(host):            
            tcdata = threatcrowd.ip_report(host)
        else:
            tcdata = threatcrowd.domain_report(host)
        
        tcurl = tcdata.get('permalink','')
        
        tcresolutions = tcdata.get('resolutions',[])
        tcresolutionslist = []
        for resolution in tcresolutions:
            if resolution.has_key('domain'):
                tcresolutionslist.append(resolution.get('domain',''))
            elif resolution.has_key('ip_address'):
                tcresolutionslist.append(resolution.get('ip_address',''))
        tcresolutionsout = '\n'.join(tcresolutionslist)

        tcvotes = tcdata.get('votes','')

        tcreferences = '\n'.join(tcdata.get('references',[]))

        tchashes = '\n'.join(tcdata.get('hashes',[]))

        tcsubdomains = '\n'.join(tcdata.get('subdomains',[]))

        tcemails = '\n'.join(tcdata.get('emails',[]))
        
        inputrow.append(tcurl)
        inputrow.append(tcvotes)
        inputrow.append(tcreferences)
        inputrow.append(tchashes)
        inputrow.append(tcresolutionsout)
        inputrow.append(tcsubdomains)
        inputrow.append(tcemails)
