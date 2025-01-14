## 필요 데이터 선언부
listProtocolMAC = list()
listMACHardwareType = list()
listMacOperationCode = list()
listIPV4Protocol = {1: "Internet Control Message Protocol(ICMP)", 
                    2: "Internet Group Management Protocol(IGMP)",
                    6: "Transmission Control Protocol(TCP)",
                    17: "User Datagram Protocol(UDP)",
                    41: "IPv6 encapsulation(ENCAP)",
                    89: "Open Shortest Path First(OSPF)",
                    132: "Stream Control Transmission Protocol(SCTP)"
                }
listIPV6NextHeader = list()
listWellKnownPort = list()


## 각종 프로토콜 패킷 고정 길이 데이터
nMACProtocolLen = 14
nARPProtocolLen = 28
nIPv6ProtocolLen = 40
