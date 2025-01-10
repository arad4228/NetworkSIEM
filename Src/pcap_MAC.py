import libpcap as pcap
import ctypes as ct
import csv

global listTypeMac
listTypeMac = list()

## 14 byte의 MAC 헤더를 분리하고, 해당 프로토콜을 찾는 것이 목적.
def Split_MACHeader(data):
    # check if load MAC Type
    global listTypeMac
    if len(listTypeMac) == 0:
        __readMACTypeCSV()
    Destination_MAC = 'BROADCAST' if bytes(data[:6]).hex().lower() == 'ffffffffffff' else bytes(data[:6]).hex()
    Source_MAC = bytes(data[6:12])
    Type_MAC = bytes(data[12:14])

    # 성능 관점에서 나중에 binary Search로 변경
    TargetMac = next((row['Protocol'] for row in listTypeMac if Type_MAC.hex().upper() in row['EtherType']), Type_MAC.hex().upper())
    
    print("Destination MAC\t\t\tSource MAC\t\t\tMAC TYPE")
    print(f"{Destination_MAC}\t\t\t{Source_MAC.hex()}\t\t\t{TargetMac}")
    return TargetMac


def __readMACTypeCSV():
    global listTypeMac
    with open("./MAC_Protocol.csv", 'r') as f:
        listTypeMac = list(csv.DictReader(f))