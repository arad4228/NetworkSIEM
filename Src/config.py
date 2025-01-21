## 필요 데이터 선언부
listProtocolMAC = list()
listMACHardwareType = list()
listMacOperationCode = list()
listIPV4Protocol = {1: "Internet Control Message Protocol", 
                    2: "Internet Group Management Protocol",
                    6: "Transmission Control Protocol",
                    17: "User Datagram Protocol",
                    41: "IPv6 encapsulation",
                    89: "Open Shortest Path First",
                    132: "Stream Control Transmission Protocol"
                }
listIPV6NextHeader = list()
listWellKnownPort = list()
listICMPProtocol = list()
listDNSRRType = list()
listDNSOPCodeClassType = list()
listSvcParamkeys = {
    0: "mandatory",
    1: "alpn",
    2: "no-default-alpn",
    3: "port",
    4: "ipv4hint",
    5: "ech",
    6: "ipv6hint",
    7: "dohpath",
    8: "ohttp",
}

## 각종 프로토콜 패킷 고정 길이 데이터
nMACProtocolLen = 14
nARPProtocolLen = 28
nIPv6ProtocolLen = 40
