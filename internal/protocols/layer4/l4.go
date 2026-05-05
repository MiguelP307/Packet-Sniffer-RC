package layer4

import "sniffer/internal/model"

type L4Handler func(data []byte, parsedPacket *model.ParsedPacket) (uint16, uint16, []byte)

var Handlers = map[uint8]L4Handler{
	1: HandleICMP,
	6: HandleTCP,
	17: HandleUDP,
	58: HandleICMPv6,
}

var Protocols = map[uint8]string{
	1: "ICMP",
	6: "TCP",
	17: "UDP",
	58: "ICMPv6",
}