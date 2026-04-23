package layer4

import "sniffer/internal/model"

type L4Handler func(data []byte, parsedPacket *model.ParsedPacket) (uint16, uint16, []byte)

var Handlers = map[uint8]L4Handler{
	1: HandleICMP,
	6: HandleTCP,
	//17: HandleUDP,
	//58: HandleICMPv6,
}