#
# INCLUDES
#
import libs.network

#
# CLASSES
#

class DNSInfo(object):
    """
    Class for DNSInfo items.
    """
    def __init__(self):
        pass

    def add_headers(self,inputlist):
        inputlist.append('IPv4')
        inputlist.append('FQDN')

    def add_row(self, host, inputrows):
        if libs.network.IsIPv4(host):
            ipv4 = host
            fqdn = '; '.join(map(str,libs.network.DNSLookupHost(host)))
        else:
            ipv4 = '; '.join(map(str,libs.network.DNSLookupHost(host)))
            fqdn = host
        inputrows.append(ipv4)
        inputrows.append(fqdn)

