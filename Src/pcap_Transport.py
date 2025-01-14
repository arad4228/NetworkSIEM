from collections import OrderedDict
from abc import abstractmethod, ABC
import config
import json
import csv

class CTransport(ABC):
    def __init__(self, TransType):
        super().__init__()
        self.TransportType = TransType

    @abstractmethod
    def serializeData(self, data):
        pass

    @abstractmethod
    def printData(self):
        pass

    @abstractmethod
    def getNextProtocol(self):
        pass

    def getProtocolType(self):
        return self.TransportType

class CTCP(CTransport):
    def __init__(self):
        super().__init__("tcp")
        self.TCPHeader = OrderedDict()
        if len(config.listWellKnownPort) == 0:
            self.__readWellKnownPortCSV()

    def serializeData(self, data):
        self.TCPHeader['Source Port'] = int.from_bytes(data[0:2])
        self.TCPHeader['Destination Port'] = int.from_bytes(data[2:4])
        self.TCPHeader['Sequence Number'] = int.from_bytes(data[4:8])
        self.TCPHeader['ACKNumber'] = int.from_bytes(data[8:12])
        DataOffset = (data[12] & 0xF0) >> 4
        self.TCPHeader['Data Offset'] = DataOffset
        self.TCPHeader['Reserved'] = (data[12] & 0x0F)
        CEUAPRSG = data[13] # CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
        flags = ['CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']
        for i, flag in enumerate(flags):
            self.TCPHeader[flag] = (CEUAPRSG >> (7 - i)) & 1
        self.TCPHeader['Window'] = int.from_bytes(data[14:16])
        self.TCPHeader['CheckSum'] = int.from_bytes(data[16:18])
        self.TCPHeader['UrgentPoint'] = int.from_bytes(data[18:20])

        if DataOffset > 5: # Options 필드가 있다면, 그냥 묶어서 hex화.
            self.TCPHeader['Options'] = data[20: 20 + DataOffset*4].hex()
        
        self.TCPDataLoc = 20 + DataOffset*4

    def getLastTCPHeaderLocation(self):
        return self.TCPDataLoc
    
    def printData(self):
        jsonData = json.dumps(self.TCPHeader, sort_keys=False, indent=4)
        print(jsonData)

    def getNextProtocol(self, port):
        # if Destination Port is Well Known Prots
        ProtocolType = self.getProtocolType()
        NextProtocol = next((row['Description'] for row in config.listWellKnownPort if (str(port) in row['Port Number']) and (ProtocolType in row['Transport Protocol'])), "TCP")
        return NextProtocol
    
    def getReceiverPort(self):
        return self.TCPHeader['Destination Port']

    def __readWellKnownPortCSV(self):
        with open("./Resource/Well_Known_Ports.csv", 'r') as f:
            config.listWellKnownPort = list(csv.DictReader(f))

class CUDP(CTransport):
    def __init__(self):
        super().__init__("udp")
        self.UDPHeader = OrderedDict()