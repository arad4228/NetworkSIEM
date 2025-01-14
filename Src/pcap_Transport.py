from collections import OrderedDict

class CTCP():
    def __init__(self):
        pass

    def split_TCPPacket(self, data):
        self.TCPData = OrderedDict()
        SourcePort = data[0:2]
        DestinationPort = data[2:4]
        SequenceNumber = data[4:8]
        ACKNumber = data[8:12]
        DataOffset = (data[12] & 0xF0) << 4
        Reserved = (data[12] & 0x0F)
        CEUAPRSG = data[13] # CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
        for i in range(8):
            ret = CEUAPRSG >> i

        Window = int.from_bytes(data[14:16])
        CheckSum = int.from_bytes(data[16:18])
        UrgentPoint = int.from_bytes(data[18:20])

        if DataOffset > 5: # Options 필드가 있다면, 그냥 묶어서 hex화.
            Options = data[20: DataOffset*4].hex()

