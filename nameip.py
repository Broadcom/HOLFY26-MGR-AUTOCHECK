# 05-May 2024
import socket
import sys
import ipaddress
import subprocess

# because PowerShell seems incapable of doing DNS lookups on Linux, do it in Python.

# hostname not in DNS but IP is with different name
# multiple IPs assigned to hostname
# multiple hostnames assigned to an IP

def is_ipv4(string):
    try:
        ipaddress.IPv4Network(string)
        return True
    except ValueError:
        return False

cmd = ["nslookup", sys.argv[1]]

if is_ipv4(sys.argv[1]):  # if we get an IP address on the command line
    try:
        run = subprocess.run(cmd, capture_output=True, text=True, check=True)
        dnshost = ""
        for entry in run.stdout.split('\n'):
            if entry == "":
                continue
            if 'from' in entry:
                continue
            parts = entry.split()
            host = parts[len(parts) - 1][:-1]
            if dnshost == "":
                dnshost = host
            else:                
                dnshost = f'{dnshost},{host}'
        ipaddr = sys.argv[1] # just repeat what was on the command line
        dnsip = ipaddr # if we are here then at least one record was found for the IP
    except Exception as e: # no DNS reverse record
        print(e)
        ipaddr = sys.argv[1]
        dnsip = "unknown"
        dnshost = "unknown"
else: # we got a hostname on the command line
    try:
        run = subprocess.run(cmd, capture_output=True, text=True, check=True)
        dnsip = ""
        for entry in run.stdout.split('\n'):
            if entry == "" or "Server:" in entry or "#53" in entry or "Name:" in entry :
                continue       
            if 'Non-authoritative answer' in entry:
                continue
            #print(f'entry: {entry}')
            (_, ip) = entry.split()
            if dnsip == "":
                dnsip = ip
                ipaddr = ip # use the first IP returned
            else:                
                dnsip = f'{dnsip},{ip}'
        dnshost = sys.argv[1] # just repeat what was on the command line
    except Exception as e:
        print(e)
        dnsip = "unknown"
        ipaddr = "unknown"
        dnshost = sys.argv[1]

# dns host names:
# dns IP addresses:
print(f'{dnshost}:{dnsip}:{ipaddr}')