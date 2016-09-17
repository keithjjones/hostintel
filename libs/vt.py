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

    def add_headers(self, inputheaders):
        """
        Adds appropriate headers to input list.
        """
        inputheaders.append('VirusTotal Detected URLs')
        inputheaders.append('VirusTotal Detected Communicating Samples')
        inputheaders.append('VirusTotal Detected Downloaded Samples')
        inputheaders.append('VirusTotal Link')

    def add_row(self, host, inputrow):
        """
        Adds the pulled data to the input row.
        """

        vtdetectedurls = vtdetectedcommunicatingsamples = \
            vtdetecteddownloadedsamples = vturl = ''

        if libs.network.IsIPv4(host):
            vtresponse = self.vt.get_ip_report(host)
            while "response_code" not in vtresponse or \
                    (vtresponse["response_code"] != 200 and
                     vtresponse["response_code"] != 403):
                time.sleep(60)  # Sleep for the API throttling
                vtresponse = self.vt.get_ip_report(host)
            if "results" not in vtresponse:
                vtdetectedurls = "INVALID API KEY"
            elif "detected_urls" in vtresponse["results"]:
                vtdetectedurls = str(len(vtresponse["results"]
                                     ["detected_urls"]))
            else:
                vtdetectedurls = str(0)
            if "results" not in vtresponse:
                vtdetectedcommunicatingsamples = "INVALID API KEY"
            elif "detected_communicating_samples" in vtresponse["results"]:
                vtdetectedcommunicatingsamples = str(len(vtresponse["results"]
                                                         ["detected_"
                                                          "communicating_"
                                                          "samples"]))
            else:
                vtdetectedcommunicatingsamples = str(0)
            vturl = "https://www.virustotal.com/en/ip-address/{}/information/"\
                    .format(host)
        else:
            vtresponse = self.vt.get_domain_report(host)
            while "response_code" not in vtresponse or \
                    (vtresponse["response_code"] != 200 and
                     vtresponse["response_code"] != 403):
                time.sleep(60)  # Sleep for the API throttling
                vtresponse = self.vt.get_domain_report(host)
            if "results" not in vtresponse:
                vtdetectedurls = "INVALID API KEY"
            elif "detected_urls" in vtresponse["results"]:
                vtdetectedurls = str(len(vtresponse["results"]
                                         ["detected_urls"]))
            else:
                vtdetectedurls = str(0)
            if "results" not in vtresponse:
                vtdetectedcommunicatingsamples = "INVALID API KEY"
            elif "detected_communicating_samples" in vtresponse["results"]:
                vtdetectedcommunicatingsamples = str(len(vtresponse["results"]
                                                         ["detected_"
                                                          "communicating_"
                                                          "samples"]))
            else:
                vtdetectedcommunicatingsamples = str(0)
            if "results" not in vtresponse:
                vtdetecteddownloadedsamples = "INVALID API KEY"
            elif "detected_downloaded_samples" in vtresponse["results"]:
                vtdetecteddownloadedsamples = str(len(vtresponse["results"]
                                                      ["detected_"
                                                       "downloaded_"
                                                       "samples"]))
            else:
                vtdetecteddownloadedsamples = str(0)
            vturl = "https://www.virustotal.com/en/domain/{}/information/"\
                    .format(host)

        inputrow.append(vtdetectedurls)
        inputrow.append(vtdetectedcommunicatingsamples)
        inputrow.append(vtdetecteddownloadedsamples)
        inputrow.append(vturl)
