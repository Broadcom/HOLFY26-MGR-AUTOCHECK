#!/usr/bin/python3
# runwincmd.py version 1.0 03-March 2024
import sys
import lsfunctions as lsf
"""
Used by AutoCheck to run a command on a remote Windows machine
from the Manager VM
"""
#ctr = 0
#for arg in sys.argv:
#    print(f'{ctr} {arg}')
#    ctr += 1

server = sys.argv[1]
user = sys.argv[2]
pw = sys.argv[3]
wcmd = sys.argv[4]
result = lsf.runwincmd(wcmd, server, user=user, pw=pw, display=True)
print(result)
