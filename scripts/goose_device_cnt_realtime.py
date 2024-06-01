###############################
# Import Python modules
###############################
import os, sys, datetime, inspect

###############################
# Import ASN1 modules
###############################
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import char
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type.univ import Boolean, Integer
import math
import struct
from datetime import datetime

###############################
# Import Scapy and Goose Modules
###############################
# We have to tell script where to find the Goose module in parent directory
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from scapy.layers.l2 import Ether
from scapy.layers.l2 import Dot1Q
from goose.ralle001_hsr import HSR
from scapy.compat import raw
from scapy.all import rdpcap
from scapy.all import sniff
from goose.goose import GOOSE
from goose.goose import GOOSEPDU
from goose.goose_pdu import *

###############################
# Global Variables
###############################
DEBUG = 0   # 0: off 1: Show Goose Payload 2: Full Debug
SHOW_PACKETS = 0    # 0: off, 1: Shows all the packets
ONLY_SHOW_DIFF = 0  # 0: shows everything, 1: Only shows packets which are different

###############################
# Import packets into SCAPY
###############################
if len(sys.argv) > 1:
    inf = sys.argv[1]
else:
    inf = None

###############################
# Identify packets containing GOOSE messages. 
# Sometimes these will be hidden within VLAN packets, so account for these
###############################

GOOSE_TYPE = 0x88b8
def gooseTest(pkt):
    isGoose = False
    # Test for a Goose Ether Type
    if pkt.haslayer('Dot1Q'):
        if pkt['Dot1Q'].type == GOOSE_TYPE: isGoose = True
    if pkt.haslayer('Ether'):
        if pkt['Ether'].type == GOOSE_TYPE: isGoose = True
    if pkt.haslayer('HSR'):
        if pkt['HSR'].type == GOOSE_TYPE: isGoose = True
    return isGoose


class GooseData:
    def __init__(self, datSet, goID, time, allData, valueList):
        self.datSet = datSet
        self.goID = goID
        self.time = time
        self.allData = allData
        self.valueList = valueList

    def getDatSet(self):
        return self.datSet

    def getGoID(self):
        return self.goID

    def getAllData(self):
        return str(self.allData)

    def addItemToList(newItem):
        valueList.append(newItem)

    def getList(self):
        return self.valueList

    def getTime(self):
        return self.time


###############################
# Process GOOSE PDU by decoding it with PYASN1
###############################
def goose_pdu_decode(encoded_data):

    # Debugging on
    if DEBUG > 2: 
        from pyasn1 import debug
        debug.setLogger(debug.Debug('all'))

    g = IECGoosePdu().subtype(
        implicitTag=tag.Tag(
            tag.tagClassApplication,
            tag.tagFormatConstructed,
            1
        )
    )
    decoded_data, unprocessed_trail = decoder.decode(
        encoded_data,
        asn1Spec=g
    )
    # This should work, but not sure.
    return decoded_data

def floating_point_converter(hex_string):
    if len(hex_string) == 8:  # 32-bit float
        format_type = '<f'  # Little-endian float
        expected_length = 4  # Number of bytes for 32-bit float
    elif len(hex_string) == 16:  # 64-bit double
        format_type = '<d'  # Little-endian double
        expected_length = 8  # Number of bytes for 64-bit double
    else:
        raise ValueError("Hexadecimal string must be either 8 or 16 characters long.")

    # Convert hexadecimal to bytes.
    bytes_data = bytes.fromhex(hex_string)
    # Check if the length of bytes matches the expected length.
    if len(bytes_data) != expected_length:
        raise ValueError("Hexadecimal string does not match the expected byte length for the given format.")
    
    # Reverse the bytes data for correct endian interpretation if necessary.
    # This step is crucial if your hardware or source uses a different byte order.
    bytes_data = bytes_data[::-1]

    # Unpack the bytes to the corresponding float or double.
    return struct.unpack(format_type, bytes_data)[0]




###############################
# Process packets and search for GOOSE
###############################
# devsrc = {src_mac:(dst_mac:goid)}
devsrc = {}
datSetList = []
gooseData = []
uniqueGoID = []
dictGoID = {}
datSet = 'datSet'
allData = 'allData'

def packet_handler(p):
    if gooseTest(p):
        # Use SCAPY to parse the Goose header and the Goose PDU header
        d = GOOSE(p.load)

        # Grab the Goose PDU for processing
        gpdu = d[GOOSEPDU].original

        # Use PYASN1 to parse the Goose PDU
        gd = goose_pdu_decode(gpdu)

        # Grab Source address, destination address, and Goose ID
        src_mac = p['Ether'].src
        dst_mac = p['Ether'].dst
        goid    = gd['goID']

        tempList = []
        
        for item in gd[allData]:
            for i in item.values():
                try:
                    # Simple floating-point
                    tempList.append(floating_point_converter(i.asOctets().hex()[2:]))
                except:
                    if type(i) != type(Boolean()) and type(i) != type(Integer()):
                        for item2 in i:
                            try:
                                for i2 in item2.values():
                                    for i3 in i2:
                                        for i4 in i3.values():
                                            # Multiple structure and floating-point
                                            tempList.append(floating_point_converter(i4.asOctets().hex()[2:]))
                            except:
                                pass
                    else:
                        # Boolean value
                        tempList.append(i)

        temp = GooseData(str(gd[datSet]), goid, p.time, gd[allData], tempList)
        gooseData.append(temp)

        # Combine stNum and t as they are related
        devgoose = (dst_mac, goid)
        if src_mac in devsrc.keys():
            if devgoose not in devsrc[src_mac]:
                devsrc[src_mac].append(devgoose)
        else:
            devsrc[src_mac] = [devgoose]

        if SHOW_PACKETS == 1:
            print('%s,%s,%s'%(src_mac, dst_mac, goid))

        datSetList.append(str(gd[datSet]))

if inf is None:
    sniff(prn=packet_handler, store=0)
else:
    sniff(prn=packet_handler, store=0, iface=inf)

###############################
# Print Statements and Functions
###############################
## Normal Print Statement
print('##################################################')
print('### Summary')
print('##################################################')
indent = '    '
print('Goose Device Count: %s\n'%(len(devsrc.keys())))

print('Source Address,Destination Address,goID')
for src_mac in devsrc.keys():
    # Print all as CSV
    for e in devsrc[src_mac]:
        # Each device should have a destination mac and a goID
        print('%s,%s,%s'%(src_mac,e[0],e[1]))

print('Select Goose packet to analyze.')
uniqueGoID = list(dict.fromkeys(datSetList))
print(len(uniqueGoID))
for e in range(len(uniqueGoID)):
    dictGoID[e] = uniqueGoID[e]
    print('[%d] %s'%(e,uniqueGoID[e]))
pnum = input('Select number:')
pnum = int(pnum)

index = 0
same = 0
tempItem = 0
print('##################################################')
print('### Analyze')
print('##################################################')
for item in gooseData:
    if dictGoID[pnum] == item.getDatSet():
        print('Message number %s'%str(index+1))
        if ONLY_SHOW_DIFF == 0:
            for i in item.getList():
                print(i)
        else:
            if tempItem != item.getAllData():
                print(item.getAllData())
        if tempItem == item.getAllData():
            same = same + 1

        tempItem = item.getAllData()
        index = index + 1


print('%s same packets'%str(same))
