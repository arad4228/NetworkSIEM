네트워크 노드 시각화 및 SIEM

## 목표
1. 네트워크 패킷 수집 및 네트워크 노드 시각화
2. 시각화된 데이터를 통한 SIEM 기능 탑제.

## 참고자료

| 대상               | 깃허브 주소                                        | 설명                                              |
|-------------------|-------------------------------------------------|--------------------------------------------------|
| SIEM              | [LogESP](https://github.com/arad4228/LogESP)    | Django 기반의 LogESP의 기능을 참고하여, SIEM 기능 업데이트 |
| Packet            | [iana](https://www.iana.org/)                   | 네트워크 패킷 프로토콜 구조 및 세부 데이터 정의 제공          |
| Packet(Ethernet)  | [EtherType](https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml) | MAC 프로토콜의 Ethernet type 데이터 제공 |
| Packet(ARP)       | [ARP Data](https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml) | ARP 프로토콜의 파라미터 데이터 제공 |
| Packet(Port)      | [Well-Known Port](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) | 잘 알려진 포트와 서비스 간 정의 데이터를 받아와 사용 |
| Packet(ICMP)      | [ICMP](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) | 각종 ICMP 파라미터와 그에 대한 스펙 제공 |
| Packet(DNS)       | [DNS Compress](https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf)     | DNS Compression관련 설명                         |
| Packet            | [Wikipedia](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) | 각종 패킷 구조 정의 제공      |
