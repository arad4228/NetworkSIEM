from collections import OrderedDict
from abc import abstractmethod, ABC
import config
import json
import csv

class CTransport(ABC):
    def __init__(self, TransType, start):
        super().__init__()
        self.TransportType = TransType
        self.start = start

    @abstractmethod
    def deserializeData(self, data):
        pass

    @abstractmethod
    def printData(self):
        pass

    @abstractmethod
    def getNextProtocol(self, pktEnd):
        pass

    @abstractmethod
    def getDataLocation(self):
        pass

    def getProtocolType(self):
        return self.TransportType
    
    def getProtocolStart(self):
        return self.start
    
class CTransportFactory:
    @staticmethod
    def getNextProtocol(Type, start):
        if Type == "Transmission Control Protocol":
            return CTCP(start)
        elif Type == "User Datagram Protocol":
            return CUDP(start)

class CTCP(CTransport):
    def __init__(self, start):
        super().__init__("tcp", start)
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

    def getDataLocation(self):
        start = self.getProtocolStart()
        return start + self.TCPData['Data Offset'] * 4
    
    def printData(self):
        jsonData = json.dumps(self.TCPData, sort_keys=False, indent=4)
        print(jsonData)

    def getNextProtocol(self, pktEnd):
        SourcePort = self.TCPData['Source Port']
        DestinationPort = self.TCPData['Destination Port']
        ProtocolType = self.getProtocolType()
        ProtocolEnd = self.start +  self.TCPData['Data Offset'] * 4
        if ProtocolEnd == pktEnd:
            return ProtocolType
        
        NextProtocol = next((row['Description'] for row in config.listWellKnownPort if (str(SourcePort) in row['Port Number']) and (ProtocolType in row['Transport Protocol'])), "Unknown")
        if NextProtocol == "Unknown":
            NextProtocol = next((row['Description'] for row in config.listWellKnownPort if (str(DestinationPort) in row['Port Number']) and (ProtocolType in row['Transport Protocol'])), "TCP")
        return NextProtocol
    
    def getData(self):
        return self.TCPData

    def __readWellKnownPortCSV(self):
        with open("./Resource/Well_Known_Ports.csv", 'r') as f:
            config.listWellKnownPort = list(csv.DictReader(f))

class CUDP(CTransport):
    def __init__(self, start):
        super().__init__("udp", start)
        self.UDPData = OrderedDict()
        if len(config.listWellKnownPort) == 0:
            self.__readWellKnownPortCSV()

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

    def getDataLocation(self):
        start = self.getProtocolStart()
        return start + 8        # UDP header Fixed Len

    def getNextProtocol(self, pktEnd):
        # if Destination Port is Well Known Prots
        SourcePort = self.UDPData['Source Port']
        DestinationPort = self.UDPData['Destination Port']        
        ProtocolType = self.getProtocolType()
        ProtocolEnd = self.start + self.UDPData['Length']
        if ProtocolEnd == pktEnd:
            return ProtocolType

        NextProtocol = next((row['Description'] for row in config.listWellKnownPort if (ProtocolType in row['Transport Protocol']) and (str(SourcePort) in row['Port Number'])), "UnKnown")
        if NextProtocol == "UnKnown":
            NextProtocol = next((row['Description'] for row in config.listWellKnownPort if (ProtocolType in row['Transport Protocol']) and (str(DestinationPort) in row['Port Number'])), "UDP")
        if NextProtocol == "UDP" and self.UDPData['Length'] == 8:
            return "End of UDP"

        return NextProtocol
    
    def getData(self):
        return self.UDPData
    
    def __readWellKnownPortCSV(self):
        with open("./Resource/Well_Known_Ports.csv", 'r') as f:
            config.listWellKnownPort = list(csv.DictReader(f))