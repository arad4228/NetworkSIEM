from collections import OrderedDict
from abc import ABC, abstractmethod
import config
import csv
import json
import socket

class CApplication(ABC):
    def __init__(self):
        super().__init__()
    
    @abstractmethod
    def deserializeData(self, data):
        pass

    @abstractmethod
    def printData(self):
        pass


class CDNS(CApplication):
    def __init__(self):
        super().__init__()
        self.DNS = OrderedDict()
        self.__readDNSDataCSV()

    def deserializeData(self, data):
        # header
        self.DNS['Transaction ID'] = int.from_bytes(data[0:2])
        Flags = int.from_bytes(data[2:4])
        listFlags = ["Query/Response", "Operation Code", "Authoritative Answer", "Truncated", "Recursion Desired", "Recirsion Available", "Reserved", "Response Code"]
        for i, flag in enumerate(listFlags):
            self.DNS[flag] = (Flags >> (7 - i)) & 1

        Question = int.from_bytes(data[4:6])
        Answer = int.from_bytes(data[6:8])
        Authority = int.from_bytes(data[8:10])
        Addition = int.from_bytes(data[10:12])
        self.DNS['Number of Questions'] = Question
        self.DNS['Number of Answer'] = Answer
        self.DNS['Number of Authority'] = Authority
        self.DNS['Number of Additional'] = Addition
        start = 12
        end = 0
        # DNS Question Section
        for i in range(Question):
            InnerDict = OrderedDict()
            start, end, Name, nName = self.__deserializeName(data, start)
            Type = int.from_bytes(data[start:start+2]) # 2bytes
            Class = int.from_bytes(data[start+2:start+4]) # 2bytes
            convertedType = next((row['TYPE'] for row in config.listDNSRRType if row['Value'] == str(Type)), "Unassigned or Private Used")
            convertedClass = next((row['ClassName'] for row in config.listDNSOPCodeClassType if row['ClassDecimal'] == str(Class)), "Reseeved")
            end += 4
            InnerDict['Name'] = Name
            InnerDict['Name Length'] = nName
            InnerDict['Type'] = convertedType
            InnerDict['Class'] = convertedClass
            self.DNS[f'Question {i+1}'] = InnerDict

        # DNS Answer
        start = end
        for i in range(Answer):
            InnerDict = OrderedDict()
            start, end, Name, nName = self.__deserializeName(data, start)
            Type = int.from_bytes(data[start:start+2])      # 2 bytes
            Class = int.from_bytes(data[start+2:start+4])   # 2 bytes
            TTL = int.from_bytes(data[start+4:start+8])     # 4 bytes
            DataLen = int.from_bytes(data[start+8:start+10])# 2 bytes
            convertedType = next((row['TYPE'] for row in config.listDNSRRType if row['Value'] == str(Type)), "Unassigned or Private Used")
            convertedClass = next((row['ClassName'] for row in config.listDNSOPCodeClassType if row['ClassDecimal'] == str(Class)), "Reseeved")
            end += 10
            start = end

            InnerDict['Name'] = Name
            InnerDict['Name Length'] = nName
            InnerDict['Type'] = convertedType
            InnerDict['Class'] = convertedClass
            InnerDict['TTL'] = TTL
            InnerDict['DataLen'] = DataLen
            InnerDict = self.__deserilizeTYPE(convertedType, data, start, DataLen, InnerDict)
            self.DNS[f'Answer {i+1}'] = InnerDict
            end += DataLen
            start = end

        # DNS Authotity
        for i in range(Authority):
            pass

        # DNS Addtionsal
        for i in range(Addition):
            pass

    
    def printData(self):
        jsonData = json.dumps(self.DNS, sort_keys=False, indent=4)
        print(jsonData)

    def __deserializeName(self, data, start, end=0):
        IStart = start   # Copy
        IEnd = IStart
        Name = ""
        nName = 0
        while True:
            if IEnd == end:
                break
            # 개별 단위 데이터 압축이 있는지 확인
            if (data[IStart] & 0xC0) == 0xC0:
               IEnd += 2
               wordLocation = int.from_bytes(data[IStart:IEnd]) & 0x3FF
               t1, t2, partialName, partialSize = self.__deserializeName(data, wordLocation) # 21번 패킷 0xC0K
               Name += partialName
               nName += partialSize
               break
            # 처음 등장했다면
            else:
               # 길이가 0이거나, 마지막이 제공한 마지막과 같다면
                if data[IStart] == 0:
                    if len(Name) != 0 and Name[-1] == '.':
                       Name = Name[:-1]
                       IEnd += 1
                    break
                IEnd = IStart + data[IStart] + 1
                nName += data[IStart] 
                IStart += 1
                Name += data[IStart:IEnd].decode("UTF-8") + "."
            IStart = IEnd
        IStart = IEnd
        return IStart, IEnd, Name, nName

    def __deserilizeTYPE(self, Type, data, start, nData, InnerDict):
        # A Type = IPaddr        
        if Type == "A":
            InnerDict['Address'] = socket.inet_ntoa(data[start:start+nData])
        elif Type == "CNAME":
            t1, t2, CName, t3 = self.__deserializeName(data, start, start+nData)
            InnerDict['CNAME'] = CName
        elif Type == "HTTPS":
            end = start
            InnerDict['SvcPriority'] = int.from_bytes(data[start:end])  # 2 bytes
            InnerDict['TargetName'] = data[start+3]                     # 1 bytes
            end += 3
            start = end
            SecondDict = OrderedDict()
            SecondDict['SvcParamKey'] = config.listSvcParamkeys.get(int.from_bytes(data[start:start+2]), int.from_bytes(data[start:start+2]))     # 2bytes
            SecondDict['SvcParamValue length'] = int.from_bytes(data[start+2:start+4])   # 2bytes(total Len)
            SecondDict['ALPN1 length'] = data[start+4]
            SecondDict['ALPN1'] = data[start+5:start+7].decode("UTF-8")
            SecondDict['ALPN2 length'] = data[start+7]
            SecondDict['ALPN2'] = data[start+8:start+10].decode("UTF-8")
            InnerDict['SvcParam'] = SecondDict
        return InnerDict

    def __readDNSDataCSV(self):
        with open("./Resource/DNSResolutionRecordType.csv", 'r') as f:
            config.listDNSRRType = list(csv.DictReader(f))
        with open("./Resource/DNSOpCodeRCodeClass.csv", 'r') as f:
            config.listDNSOPCodeClassType = list(csv.DictReader(f))