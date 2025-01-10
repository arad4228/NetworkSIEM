from pcap_MAC import *
from pcap_ARP import *
import libpcap as pcap
import ctypes as ct
import sys
import signal

# pcap Setting
# for Mac OS
pcap.config(LIBPCAP="/opt/homebrew/opt/libpcap/lib/libpcap.A.dylib")

global handler
handler = None

def packet_controller(header, pkt_data):
    ## 데이터 14바이트 이더넷(MAC)
    data = bytes(pkt_data[:14])
    type = Split_MACHeader(data)
    ## 이후 데이터 TCP
    if 'A. R. P.' in type:
        data = bytes(pkt_data[14:42])
        Split_ARPData(data) # 28byte

def getPacketData(device):
    # 오류 메시지를 담을 버퍼 생성
    global handler
    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    device = ct.c_char_p(device.encode("UTF-8"))
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
            print("Error reading the packet {}", errbuf, file=sys.stderr)            



if __name__ == "__main__":
    device = "en0"
    try:
        getPacketData(device)
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
    finally:
        if handler:
            pcap.close(handler)