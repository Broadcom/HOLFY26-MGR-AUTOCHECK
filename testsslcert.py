#!/usr/bin/python3
# version 0.2 26 April 2021
# better error handling (adfs issues)
import os
import sys
import errno
import datetime
import OpenSSL
import ssl
import socket
from ipaddress import ip_network, ip_address

class SslHost:
	"""class to record hostname and port number and SSL certificate expiration"""

	def __init__(self, name, port):
		self.name = name
		self.port = port


def test_tcp_port(server, port):
	"""
	attempt a socket connection to the host on the port
	:param server:
	:param port:
	:return: boolean, true it connection is sucessful
	"""
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect((server, int(port)))
		s.shutdown(2)
		return True
	except IOError:
		return False


def get_ssl_host_from_url(u):
	"""
	get the host and port substrings from a URL
	:param u: string type, the URL with the host name to extract
	:return: SslHost object with name and port
	"""
	j = u.split('/')
	if j[2].find(':') == -1:  # no port number so assume 443
		name = str(j[2])
		port = 443
	else:
		p = j[2].split(':')  # in case there is a port number
		name = str(p[0])
		port = str(p[1])
	return SslHost(name, port)


def get_cert_expiration(ssl_cert):
	"""
	Return SSL Certificate expiration from passed in certificate.
	:param ssl_cert: str - the SSL certificate
	:return: expiration date as datetime.date from the SSL certificate information
	"""
	# x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
	x509info = ssl_cert.get_notAfter()
	exp_day = x509info[6:8].decode("utf-8")
	exp_month = x509info[4:6].decode("utf-8")
	exp_year = x509info[:4].decode("utf-8")
	return datetime.date(int(exp_year), int(exp_month), int(exp_day))


def check_proxy(u):
    """
    returns True if url is outside the vPod and False otherwise
    :param: u: the url to check for proxy use
    """
    proxy = True
    nets = ['192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8', '127.0.0.0/8']
    j = u.split('/')
    if j[2].find(':') == -1:  # no port number so assume 443
        name = str(j[2])
    else:
        p = j[2].split(':')  # in case there is a port number
        name = str(p[0])
    try:
        ip_tst = ip_address(socket.gethostbyname(name))
    except Exception as e:
        #write_output('Exception: ' + str(e) + ': ' + name)
        if 'not known' in str(e):
            res = subprocess.Popen(['ping', '-c', '3', '8.8.8.8'], stdout=subprocess.DEVNULL)
            if res != 0:
                #write_output('Cannot reach external DNS. Failing the lab.')
                #write_vpodprogress('DNS Failure', 'FAIL-1')
                return False
    for net in nets:
        range_tst = ip_network(net)
        if ip_tst in range_tst:
            proxy = False
    return proxy


# Get URL and expiration date on command line
url = sys.argv[1]
lab_year = int(sys.argv[2]) + 2000
min_exp_date = datetime.date(lab_year, 12, 30)

host = get_ssl_host_from_url(url)
if check_proxy(url):
	print(f'PASS: {url} is outside the vPod so no SSL Certificate expiration test is needed.')
	exit(0)
	
if test_tcp_port(host.name, host.port):
	try:	
		cert: str = ssl.get_server_certificate((host.name, host.port))
	except Exception as e:
		print(f'FAIL: COULD NOT TEST {url} {e}')
		exit(2)
	# noinspection PyTypeChecker
	x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
	subject = x509.get_subject()
	host.certname = subject.CN  # the Common Name field
	issuer = x509.get_issuer()
	# host.issuer = 'OU=' + issuer.OU + 'O=' + issuer.O
	host.ssl_exp_date = get_cert_expiration(x509)
	host.days_to_expire = str((host.ssl_exp_date - min_exp_date).days)
	if int(host.days_to_expire) < 1:		
		print(f'FAIL: expires {host.ssl_exp_date} {host.days_to_expire} days *** EXPIRES BEFORE {min_exp_date} ***')
	else:
		print(f'PASS: expires {host.ssl_exp_date} {host.days_to_expire} days past {min_exp_date}')
else:
	print(f'FAIL: COULD NOT TEST {url}')
