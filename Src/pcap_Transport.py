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
    def deserializeData(self, data):
        pass

    @abstractmethod
    def printData(self):
        pass

    @abstractmethod
    def getNextProtocol(self):
        pass

    @abstractmethod
    def getDataLocation(self, Start):
        pass

    def getProtocolType(self):
        return self.TransportType

class CTCP(CTransport):
    def __init__(self):
        super().__init__("tcp")
        self.TCPData = OrderedDict()
        if len(config.listWellKnownPort) == 0:
            self.__readWellKnownPortCSV()

    def deserializeData(self, data):
        self.TCPData['Source Port'] = int.from_bytes(data[0:2])
        self.TCPData['Destination Port'] = int.from_bytes(data[2:4])
        self.TCPData['Sequence Number'] = int.from_bytes(data[4:8])
        self.TCPData['ACKNumber'] = int.from_bytes(data[8:12])
        DataOffset = (data[12] & 0xF0) >> 4
        self.TCPData['Data Offset'] = DataOffset
        self.TCPData['Reserved'] = (data[12] & 0x0F)
        CEUAPRSG = data[13] # CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
        flags = ['CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']
        for i, flag in enumerate(flags):
            self.TCPData[flag] = (CEUAPRSG >> (7 - i)) & 1
        self.TCPData['Window'] = int.from_bytes(data[14:16])
        self.TCPData['CheckSum'] = int.from_bytes(data[16:18])
        self.TCPData['UrgentPoint'] = int.from_bytes(data[18:20])

        if DataOffset > 5: # Options 필드가 있다면, 그냥 묶어서 hex화.
            self.TCPData['Options'] = data[20: 20 + DataOffset*4].hex()

    def getDataLocation(self, Start):
        return Start + self.TCPData['Data Offset'] * 4
    
    def printData(self):
        jsonData = json.dumps(self.TCPData, sort_keys=False, indent=4)
        print(jsonData)

    def getNextProtocol(self, TCPStart, TotalSize):
        Port = self.TCPData['Destination Port']
        if self.getDataLocation(TCPStart) == TotalSize:
            return "TCP"
        
        # if Destination Port is Well Known Prots
        ProtocolType = self.getProtocolType()
        NextProtocol = next((row['Description'] for row in config.listWellKnownPort if (str(Port) in row['Port Number']) and (ProtocolType in row['Transport Protocol'])), "TCP")
        return NextProtocol
    
    def getData(self):
        return self.TCPData

    def __readWellKnownPortCSV(self):
        with open("./Resource/Well_Known_Ports.csv", 'r') as f:
            config.listWellKnownPort = list(csv.DictReader(f))

class CUDP(CTransport):
    def __init__(self):
        super().__init__("udp")
        self.UDPData = OrderedDict()

    def deserializeData(self, data):
        self.UDPData['Source Port'] = int.from_bytes(data[0:2])
        self.UDPData['Destination Port'] = int.from_bytes(data[2:4])
        self.UDPData['Length'] = int.from_bytes(data[4:6])
        self.UDPData['Checksum'] = int.from_bytes(data[6:8])
        try:
            self.UDPData['Data'] = data[8:].decode('UTF-8')
        except:
            self.UDPData['Data'] = data[8:].hex()

    def printData(self):
        jsonData = json.dumps(self.UDPData, sort_keys=False, indent=4)
        print(jsonData)

    def getDataLocation(self, Start):
        return Start + self.UDPData['Length'] * 4

    def getNextProtocol(self, UDPStart, TotalSize):
        # if Destination Port is Well Known Prots
        Port = self.UDPData['Destination Port']
        if self.getTCPDataLocation(UDPStart) == TotalSize:
            return "UDP"
        
        ProtocolType = self.getProtocolType()
        NextProtocol = next((row['Description'] for row in config.listWellKnownPort if (str(Port) in row['Port Number']) and (ProtocolType in row['Transport Protocol'])), "UDP")
        return NextProtocol
    
    def getData(self):
        return self.UDPData