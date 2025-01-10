import libpcap as pcap
import ctypes as ct
import sys
import signal
# pcap Setting
pcap.config(LIBPCAP="/opt/homebrew/opt/libpcap/lib/libpcap.A.dylib")
global packet
packet = None
@pcap.pcap_handler
def countme(arg, hdr, pkt):
    counterp = ct.cast(arg, ct.POINTER(ct.c_int))
    counterp[0] += 1
def sigint_handler(signum, frame):
    global packet
    print("\nCTRL+C pressed. Stopping packet capture...")
    pcap.breakloop(packet)
def getPacketData(device):
    # 오류 메시지를 담을 버퍼 생성
    global packet
    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    packet = pcap.create(device.encode("UTF-8"), errbuf)
    # 패킷이 구성되지 않았다면
    if not packet:
        print("FAIL: Unexpected error from pcap.create() ({}).".format(errbuf), file=sys.stderr)
        exit(-1)
    # 에러 버퍼 초기화
    errbuf[0] = b"\0"
    # 캡처할 최대 길이 설정
    status = pcap.set_snaplen(packet, 65535)
    if status != 0:
        print("{}: pcap.set_snaplen failed: {}".format(device, status), file=sys.stderr)
        exit(-1)
    # pcap이 packet을 잡도록 수행
    status = pcap.activate(packet)
    if status < 0:
        # pcap.activate() failed.
        print("{}: {}\n({})",device, status, packet, file=sys.stderr)
    elif status > 0:
        # pcap.activate() succeeded, but it's warning us
        # of a problem it had.
        print("{}: {}\n({})",device, status, packet, file=sys.stderr)
    print("Listening on {}".format(device))
    while True:
        packet_count = ct.c_int(0)
        status = pcap.dispatch(packet, -1, countme,
                    ct.cast(ct.pointer(packet_count), ct.POINTER(ct.c_ubyte)))
        if status < 0:
            break
        if status != 0:
            print("{:d} packets seen, {:d} packets counted after "
                    "pcap.dispatch returns".format(status, packet_count.value))
            ps = pcap.stat()
            if pcap.stats(packet, ct.byref(ps)) < 0:
                print("pcap.stats: {}".format(packet), file=sys.stderr)
            else:
                print("{:d} ps_recv, {:d} ps_drop, {:d} ps_ifdrop".format(
                        ps.ps_recv, ps.ps_drop, ps.ps_ifdrop))
if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint_handler)
    device = "en0"
    try:
        getPacketData(device)
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
    finally:
        if packet:
            pcap.close(packet)