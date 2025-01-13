from pcap_MAC import *
from pcap_ARP import *
from pcap_IP import *
import libpcap as pcap
import ctypes as ct
import sys

# pcap Setting
# for Mac OS
pcap.config(LIBPCAP="/opt/homebrew/opt/libpcap/lib/libpcap.A.dylib")

global handler
handler = None

def packet_controller(header, pkt_data):
    ## 헤더는 14 byte
    DataMACHeader = bytes(pkt_data[:14])

    classMACHeader = CMACHeader()
    classMACHeader.Split_MACHeader(DataMACHeader)
    
    if 'A. R. P.' in classMACHeader.getTargetProtocol():
        ARPdata = bytes(pkt_data[14:42])
        Source = classMACHeader.getSourceMAC()
        Destination = classMACHeader.getDestinationMAC()
        protocol = classMACHeader.getTargetProtocol()

        classARP = CARP(Source, Destination, protocol)
        classARP.Split_ARPData(ARPdata)
    elif "IP" in classMACHeader.getTargetProtocol():
        VIHL = pkt_data[14]      # Version, IHL
        Version = VIHL >> 4
        IHL = VIHL & 0x0F  
        if Version == 4:
            IPHeader = bytes(pkt_data[14: 14+(IHL*4)])
            classIPHeader = CIPV4Header()
            classIPHeader.Split_IPV4Header(IPHeader)
        else:
            IPHeader = bytes(pkt_data[14:54])        #  Fixed 40 bytes
            classIPHeader = CIPV6Header()
            classIPHeader.Split_IPV6Header(IPHeader)
        classIPHeader.PrintTCPData()


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
    typeWork = "Nomal"   # Test / Nomal
    file = "./TestFile/TestIPv6.pcap"
    try:
        getPacketData(device, typeWork, file)
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
    finally:
        if handler:
            pcap.close(handler)