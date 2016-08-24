#
# INCLUDES
#

# Required for VirusTotal API
from virus_total_apis import PublicApi as VirusTotalPublicApi
# Required for sleep function
import time
# Required network functions
import libs.network

#
# CLASSES
#

class VT(object):
    """
    Class to hold VirusTotal items.
    """

    #
    # FUNCTIONS
    #
    """
    Sets up a VirusTotal object with the public api.
    """
    def __init__(self, vtpublicapi):
        self.vtpublicapi = vtpublicapi
        self.vt = VirusTotalPublicApi(self.vtpublicapi)

    """
    Adds appropriate headers to input list.
    """
    def add_headers(self,inputheaders):
        inputheaders.append('VirusTotal Detected URLs')
        inputheaders.append('VirusTotal Detected Communicating Samples')
        inputheaders.append('VirusTotal Detected Downloaded Samples')
        inputheaders.append('VirusTotal Link')

    """
    Adds the pulled data to the input row.
    """
    def add_row(self,host,inputrow):

        vtdetectedurls = vtdetectedcommunicatingsamples = \
            vtdetecteddownloadedsamples = vturl = ''
        
        if libs.network.IsIPv4(host):
            vtresponse = self.vt.get_ip_report(host)
            while vtresponse["response_code"] != 200 and vtresponse["response_code"] != 403:
                time.sleep(60)  # Sleep for the API throttling
                vtresponse = self.vt.get_ip_report(host)
            if not vtresponse.has_key("results"):
                vtdetectedurls = "INVALID API KEY"            
            elif vtresponse["results"].has_key("detected_urls"):
                vtdetectedurls = str(len(vtresponse["results"]["detected_urls"]))
            else:
                vtdetectedurls = str(0)
            if not vtresponse.has_key("results"):
                vtdetectedcommunicatingsamples = "INVALID API KEY"
            elif vtresponse["results"].has_key("detected_communicating_samples"):
                vtdetectedcommunicatingsamples = str(len(vtresponse["results"]["detected_communicating_samples"]))
            else:
                vtdetectedcommunicatingsamples = str(0)
            vturl = "https://www.virustotal.com/en/ip-address/{}/information/".format(host)
        else:
            vtresponse = self.vt.get_domain_report(host)
            while vtresponse["response_code"] != 200 and vtresponse["response_code"] != 403:
                time.sleep(60)  # Sleep for the API throttling
                vtresponse = self.vt.get_domain_report(host)
            if not vtresponse.has_key("results"):
                vtdetectedurls = "INVALID API KEY"
            elif vtresponse["results"].has_key("detected_urls"):
                vtdetectedurls = str(len(vtresponse["results"]["detected_urls"]))
            else:
                vtdetectedurls = str(0)
            if not vtresponse.has_key("results"):
                vtdetectedcommunicatingsamples = "INVALID API KEY"
            elif vtresponse["results"].has_key("detected_communicating_samples"):
                vtdetectedcommunicatingsamples = str(len(vtresponse["results"]["detected_communicating_samples"]))
            else:
                vtdetectedcommunicatingsamples = str(0)
            if not vtresponse.has_key("results"):
                vtdetecteddownloadedsamples = "INVALID API KEY"
            elif vtresponse["results"].has_key("detected_downloaded_samples"):
                vtdetecteddownloadedsamples = str(len(vtresponse["results"]["detected_downloaded_samples"]))
            else:
                vtdetecteddownloadedsamples = str(0)
            vturl = "https://www.virustotal.com/en/domain/{}/information/".format(host)

        inputrow.append(vtdetectedurls)
        inputrow.append(vtdetectedcommunicatingsamples)
        inputrow.append(vtdetecteddownloadedsamples)
        inputrow.append(vturl)
