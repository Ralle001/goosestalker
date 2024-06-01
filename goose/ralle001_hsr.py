from scapy.all import *

class HSR(Packet):
    name = "HSR"
    fields_desc = [
        BitField("path",0,4),
        BitField("network_id",0,4),
        BitField("lane_id",0,4),
        BitField("LSDU_size",0,4),
        ShortField("sequence_number",0),
        ShortField("type",0),
    ]

bind_layers(Ether, HSR, type=0x892f)