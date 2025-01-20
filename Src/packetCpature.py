from pcap_Network import *
from pcap_Internet import *
from pcap_InternetOver import *
from pcap_Transport import *
from pcap_Application import *
import libpcap as pcap
import ctypes as ct
import sys

# pcap Setting
# for Mac OS
pcap.config(LIBPCAP="/opt/homebrew/opt/libpcap/lib/libpcap.A.dylib")

global handler
handler = None

## 각각 처리하는 함수를 파일에 만들어 놓기
def packet_controller(header, pkt_data):
    # Internet(MAC Protocol) # 14 bytes
    start = 0
    end = config.nMACProtocolLen
    DataMACHeader = bytes(pkt_data[:end])
    classMACHeader = CMAC()
    classMACHeader.deserializeData(DataMACHeader)

    # Internet(ARP, RARP, IPv4, IPv6)
    start = end
    VIHL = pkt_data[start]      # Version, IHL
    Version = VIHL >> 4
    # Cisco와 같은 안알려진 데이터 처리를 위한 예외 처리 도입 필요
    try:
        InternetProtocol = CInternetFactory.getNextProtocol(classMACHeader.getTargetProtocol(), Version)
        if InternetProtocol == None:
            raise Exception(f"등록되지않은 EtherType: {classMACHeader.getTargetProtocol()}")
    except Exception as e:
        print(e)
        end = header.contents.len
        data = {"data": (bytes(pkt_data[start:end]).hex())}
        classMACHeader.addDataForUnknownType(data)
        classMACHeader.printData()
        return
    
    Protocoldata = ""
    # ARP, RPARP
    if 'ARP' in InternetProtocol.getProtocolName():
        end += config.nARPProtocolLen
        Protocoldata = bytes(pkt_data[start:end])
    elif "IPv4" == InternetProtocol.getProtocolName():
        VIHL = pkt_data[start]      # Version, IHL
        IHL = VIHL & 0x0F
        end += IHL * 4
        Protocoldata = bytes(pkt_data[start: end])
    elif  "IPv6" == InternetProtocol.getProtocolName():
        end += config.nIPv6ProtocolLen
        Protocoldata = bytes(pkt_data[start:end])        #  Fixed 40 bytes
    else:
        raise Exception("올바르지 않은 IP Version입니다.")
    InternetProtocol.deserializeData(Protocoldata)  
    # classIPHeader.printData()

    start = end
    TransportProtocol = CTransportFactory.getNextProtocol(InternetProtocol.getNextProtocol())
    if TransportProtocol == None:
        return
    if TransportProtocol.getProtocolType() == 'Internet Control Message Protocol':
        end = header.contents.len
        ICMPData = bytes(pkt_data[start:end])
        classICMP = CICMP()
        classICMP.deserializeData(ICMPData)
        classICMP.printData()
        return
    
    TransportData = ""
    if TransportProtocol.getProtocolType() == 'tcp':
            DataOffsetReserved = pkt_data[start + 12]
            DataOffset = ((DataOffsetReserved & 0xF0) >> 4) * 4
            end += DataOffset
            TransportData = bytes(pkt_data[start:end])
    elif TransportProtocol.getProtocolType() == 'udp':
            UDPLength = int.from_bytes(pkt_data[start + 4: start + 6])
            end += UDPLength
            TransportData = bytes(pkt_data[start:end])
    TransportProtocol.deserializeData(TransportData)
    # print(f"({TransportProtocol.getProtocolType()})Next Protocol is {TransportProtocol.getNextProtocol()}")

    if TransportProtocol.getNextProtocol() == "Domain Name Server":
        start = TransportProtocol.getDataLocation(start)
        end = header.contents.len
        DNSdata = bytes(pkt_data[start:end])
        classDNS = CDNS()
        classDNS.deserializeData(DNSdata)
        classDNS.printData()




def getPacketData(device, workType, file):
    # 오류 메시지를 담을 버퍼 생성
    global handler
    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    device = ct.c_char_p(device.encode("UTF-8"))
    
    if workType == "Test":
        file = ct.c_char_p(file.encode("UTF-8"))
        handler = pcap.open_offline(file, errbuf)
    else:
        handler = pcap.open_live(device, 65535, 1, 1, errbuf)

    # 패킷이 구성되지 않았다면
    if not handler:
        print("FAIL: Unexpected error from pcap.create() ({}).".format(errbuf), file=sys.stderr)
        exit(-1)

    # 에러 버퍼 초기화
    errbuf[0] = b"\0"

    # pcap이 packet을 잡도록 수행
    while True:
        header = ct.POINTER(pcap.pkthdr)()
        pkt_data = ct.POINTER(ct.c_ubyte)()
        result = pcap.next_ex(handler, ct.byref(header), ct.byref(pkt_data))

        if result == 1:
            packet_controller(header, pkt_data)
        elif result == 0: # time out
            continue
        else:
            print("Error reading the packet {}".format(errbuf), file=sys.stderr)
            exit(-1)           

if __name__ == "__main__":
    device = "en7"
    typeWork = "Test"   # Test / Nomal
    file = "./TestFile/TestDNS.pcap"
    try:
        getPacketData(device, typeWork, file)
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
    finally:
        if handler:
            pcap.close(handler)