#!/usr/bin/python
# Triforce Netfirm Toolbox, put into the public domain.
# Please attribute properly, but only if you want.
# ...
# ok, now you're on your own, the tools are there.
# We see the DIMM space as it's seen by the dimm-board (i.e. as on the disc).
# Good Luck. Warez are evil.
# 
# https://github.com/travistyoj/piforcetools/blob/master/triforcetools.py
#
# Trimmed down to be used for Naomi Game Genie style Patching by Finisterre
# 
# MetalliC mentioned using ArtMoney for game cheats - http://www.artmoney.ru
# This is an attempt at exploring that concept using the Triforce Toolbox
# Maybe in the future I can add some of the features of ArtMoney
# - Data type searching, Pointer searching, value search, etc. 
# 
# https://www.arcade-projects.com/forums/index.php?thread/2454-netboot-sram-backup-restore-aka-save-high-scores-and-settings/&postID=87587&highlight=artmoney#post87587
#
# Please note the examples used are just examples! There are no known memory address / value combinations for any particular game. 
#
# Example Usage:
# Read 8 characters from address 0x0
#
# $ python Naomi_GameGenie.py --ip=192.168.1.2 --addr=0x0 --len=8
# Connecting to 192.168.1.2
# Using address: 0x0
# Memory snapshot: 
# 00000000: 4E 41 4F 4D 49 20 20 20                           NAOMI   
# No write value, so not writing anything
#
# Read 100 characters from address 0xA0207512
#
# $ python Naomi_GameGenie.py --ip=192.168.1.2 --addr=0xA0207512 --len=100
# Connecting to 192.168.1.2
# Using address: 0xa0207512
# Memory snapshot: 
# 00000000: 00 00 30 47 42 42 05 01  00 01 00 01 01 01 00 00  ..0GBB..........
# 00000010: 00 00 00 00 00 00 30 47  42 42 06 01 00 01 00 01  ......0GBB......
# 00000020: 01 01 00 00 00 00 00 00  00 00 30 47 42 42 07 01  ..........0GBB..
# 00000030: 00 01 00 01 01 01 00 00  00 00 00 00 00 00 0B 08  ................
# 00000040: 00 20 20 4D 41 52 56 45  4C 5E 45 20 56 53 2E 43  .  MARVEL^E VS.C
# 00000050: 41 50 43 4F 4D 20 5E 44  20 32 00 00 00 00 00 00  APCOM ^D 2......
# 00000060: 00 00 00 00                                       ....
# No write value, so not writing anything
#
# Write the value 0x040404040404 (6 characters) to 0xA0207512, but read 24 chars from same address
# 
# $ python Naomi_GameGenie.py --ip=192.168.1.2 --addr=0xA0207512 --len=24 --value=040404040404
# Connecting to 192.168.1.2
# Using address: 0xa0207512
# Memory snapshot: 
# 00000000: 00 00 30 47 42 42 05 01  00 01 00 01 01 01 00 00  ..0GBB..........
# 00000010: 00 00 00 00 00 00 30 47                           ......0G
# Hex string for write value:
# 000030474242050100010001010100000000000000003047
# Post write memory:
# 00000000: 04 04 04 04 04 04 05 01  00 01 00 01 01 01 00 00  ................
# 00000010: 00 00 00 00 00 00 30 47                           ......0G
# 
# Write the value 0x040404040404 (6 characters) to 0xA0207512, and read *only* 6 characters from same address
#
# $ python Naomi_GameGenie.py --ip=192.168.1.2 --addr=0xA0207512 --len=6 --value=040404040404
# Connecting to 192.168.1.2
# Using address: 0xa0207512
# Memory snapshot: 
# 00000000: 04 04 04 04 04 04                                 ......
# Hex string for write value:
# 040404040404
# Post write memory:
# 00000000: 04 04 04 04 04 04                                 ......

import getopt, sys

import hexdump
import binascii
import struct, sys
import socket
import time
from Crypto.Cipher import DES

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)

# a function to receive a number of bytes with hard blocking
def readsocket(n):
	res = ""
	while len(res) < n:
		res += s.recv(n - len(res))
	return res

def HOST_Restart():
	s.send(struct.pack("<I", 0x0A000000))

# Read a number of bytes (up to 32k) from DIMM memory
def DIMM_Read(addr, size):
	s.send(struct.pack("<III", 0x05000008, addr, size))
	return readsocket(size + 0xE)[0xE:]

def DIMM_Write(addr, data):
	s.send(struct.pack("<IIIH", 0x04800000 | (len(data) + 0xA) | (0 << 16), 0, addr, 0) + data) # DIMM_Upload() with Hardcoded "mark" value set to 0, not sure what it was. 

def usage():
    print "For more examples, see the header of the program source code..."
    print "Ex: Read 8 bytes of memory from 0x0" # Expect "NAOMI" magic word in return
    print "    $ python Naomi_GameGenie.py --ip=192.168.1.2 --addr=0x0 --len=8"
    print "Ex: Write the 6 byte value 0x040404040404 to 0xA0207512"
    print "    $ python Naomi_GameGenie.py --ip=192.168.1.2 --addr=0xA0207512 --len=6 --value=040404040404"
    print "Ex: Read the default of 4 bytes from 0xA0207512"
    print "    $ python Naomi_GameGenie.py --ip=192.168.1.2 --addr=0xA0207512"

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hiavl", ["help", "ip=","addr=", "value=", "len="])
    except getopt.GetoptError, err:
        # print help information and exit:
        print str(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    ip = None
    addr = None
    value = None
    length = None
    ro = False

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-i", "--ip"):
            ip = a
        elif o in ("-a", "--addr"):
            addr = int(a, 0)
        elif o in ("-v", "--value"):
            value = a
        elif o in ("-l", "--len"):
            length = int(a)
        else:
            assert False, "unhandled option"

    if ip is None:
	naomi_ip = "192.168.1.2"
    else:
        naomi_ip = ip

    print "Connecting to " + naomi_ip
    s.connect((naomi_ip, 10703))

    if addr is None:
	print "Please supply a write address"
        sys.exit(0)
    print "Using address: " + hex(addr)

    if length is None:
        print "No length supplied, using 4 as default"
        length = 4

    print "Memory snapshot: "
    dimm_mem = DIMM_Read(addr, length)
    hexdump.hexdump(dimm_mem)
    print "Hex string for write value:"
    print binascii.hexlify(dimm_mem)

    if value is not None:
        try:
            DIMM_Write(addr,  binascii.unhexlify(value))
        except TypeError:
            print "Your hex string is missing a char!"
            sys.exit(0)
            
        print "Post write memory:"
        dimm_mem = DIMM_Read(addr, length)
        hexdump.hexdump(dimm_mem)
    else: 
        print "No write value, so not writing anything"

if __name__ == "__main__":
    main()
