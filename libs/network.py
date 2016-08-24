#
# INCLUDES
#

# Required for regular expressions
import re
# Required for DNS lookups
import dns.resolver

#
# FUNCTIONS
#

"""
Function to determine if host is an IPv4 address
"""
def IsIPv4(host):
    if re.match('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',host):
        return True
    else:
        return False

"""
Function to determine if host is a domain (only one period in host)
"""
def IsDomain(host):
    if re.match('[^\.]*\.[^\.]*',host):
        return True
    else:
        return False

"""
Function to determine if host is a FQDN host name
"""
def IsFQDN(host):
    if IsIPv4(host) or IsDomain(host):
        return False
    else:
        return True

"""
Function to create reverse lookup address, inspired by:
http://www.iodigitalsec.com/performing-dns-queries-python/
"""
def ReverseAddress(IP):
    RevIP = '.'.join(reversed(IP.split('.'))) + '.in-addr.arpa'
    return RevIP

"""
Function to DNS lookup host
"""
def DNSLookupHost(host):
    try:
        if IsIPv4(host):
            return dns.resolver.query(ReverseAddress(host),'PTR')
        else:
            return dns.resolver.query(host,'A')
    except:
        return []
