#!/usr/bin/python3
# 12-May 2025
#
# This Python script shows how to make basic REST API calls to an NSX
# Manager Server.
#
# More information on the NSX Manager REST API is here:
# http://pubs.vmware.com/nsx-63/topic/com.vmware.ICbase/PDF/nsx_63_api.pdf
# https://pubs.vmware.com/NSX-6/topic/com.vmware.ICbase/PDF/nsx_604_api.pdf

import sys
import os
import socket
import subprocess
import base64
import ssl
import json
import urllib.request
from configparser import ConfigParser


authorizationField = ''
configname = 'config.ini'


def nsxSetup(username, password):
   '''Setups up Python's urllib library to communicate with the
      NSX Manager.  Uses TLS 1.2 and no cert, for demo purposes.
      Sets the authorization field you need to put in the
      request header into the global variable: authorizationField.
   '''
   global authorizationField

   context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
   context.verify_mode = ssl.CERT_NONE
   httpsHandler = urllib.request.HTTPSHandler(context = context)

   manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
   authHandler = urllib.request.HTTPBasicAuthHandler(manager)

   # The opener will be used for for all urllib calls, from now on.
   opener = urllib.request.build_opener(httpsHandler, authHandler)
   urllib.request.install_opener(opener)

   basicAuthString = '%s:%s' % (username, password)
   field = base64.b64encode(basicAuthString.encode('ascii'))
   #Debugging: print('Basic %s' % str(field,'utf-8'))
   authorizationField = 'Basic %s' % str(field,'utf-8')


def nsxGet(url):
   '''Does a HTTP GET on the NSX Manager REST Server.
      If a second argument is given, the result is stored in a file
      with that name.  Otherwise, it is written to standard output.
   '''
   global authorizationField

   request = urllib.request.Request(url,
             headers={'Authorization': authorizationField})
   response = urllib.request.urlopen(request)
   return(response.read().decode())



# get the password for the vPod
bad_sku = 'HOL-BADSKU'
lab_sku = bad_sku
configtmp = ConfigParser()
configtmp.read(f'/tmp/{configname}')
lab_sku = configtmp.get('VPOD', 'vPod_SKU')
lab_year = lab_sku[4:6]
lab_num = lab_sku[6:8]
vpod_repo = f'/vpodrepo/20{lab_year}-labs/{lab_year}{lab_num}'
if os.path.exists(f'{vpod_repo}/{configname}'):
   configini = f'{vpod_repo}/{configname}'
else:
   configini = f'/tmp/{configname}'
# Read the latest config.ini file to set globals
config = ConfigParser()
config.read(configini)
creds = '/home/holuser/creds.txt'
with open(creds, 'r') as c:
    p = c.readline()
    nsxpw = p.strip()

hostname = sys.argv[1]
ip = sys.argv[2]
target = f'{hostname}({ip})'
user = 'admin'

#check if SSH active for the NSX Manager appliance
sshaccess = False
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect((hostname, int(22)))
    s.shutdown(2)
    sshaccess = True
except IOError:
    print(f'FAIL~{target}~NSX password expiration~Cannot check password expiration. SSH access not enabled.')
    sshaccess = False

if sshaccess:
    # check accounts password expiration
    nsxusers = ["admin", "root", "audit"]
    sshoptions = '-o StrictHostKeyChecking=accept-new'
    for nsxuser in nsxusers:
        cmd = f'get user {nsxuser} password-expiration'
        rh = f'{nsxuser}@{hostname}'
        rcmd = f'/usr/bin/sshpass -p {nsxpw} ssh {sshoptions} {rh} {cmd}'  # 2>&1
        rcmdlist = rcmd.split()
        try:
            run = subprocess.run(rcmdlist, capture_output=True, text=True, check=True)
            if 'expires' in run.stdout:
               print(f'FAIL~{target}t~NSX password expiration~Please clear user password expiration for {nsxuser}.')
            elif 'expiration not configured for this user' in run.stdout:
               print(f'PASS~{target}t~NSX password expiration~Password for {nsxuser} has no expiration. Thanks.')
        except Exception as e:
            print(f'FAIL~{target}~NSX password expiration~Cannot check password expiration for {nsxuser}.')

print("\n") # need a line feed

# cannot check licensing on an Edge
if 'edge' in hostname:
    exit(0)

# check NSX license expiration
try:
    nsxSetup(user,nsxpw)
    jsondata = nsxGet(f'https://{hostname}/api/v1/licenses')
    jsondict = json.loads(jsondata)
    for result in jsondict["results"]:
        if result["description"] != 'NSX for vShield Endpoint':
            licdesc = result["description"]
            if result["expiry"] == 0:
                print(f'FAIL~{target}~NSX licensing~{licdesc} is a permanent license')
            elif result["is_eval"] == 'true':
                print(f'FAIL~{target}~NSX licensing~{licdesc} is an evaluation license')
            else:
                expiry = result["expiry"]
                # Using the "!" to delimit the expiration date for PowerShell
                print(f'WARN~{target}~NSX licensing~{licdesc}:{expiry}')
except Exception as e:
    print(f'FAIL~{target}~NSX licensing~Cannot check license expiration for {hostname}. {e}')
