package layer3

import "sniffer/internal/model"

type L3Handler func(data []byte, parsedPacket *model.ParsedPacket) (uint8, []byte)

var Handlers = map[uint16]L3Handler{
	0x0800: HandleIPv4,
	//0x0806: HandleARP,
	//0x86DD: HandleIPv6,
}