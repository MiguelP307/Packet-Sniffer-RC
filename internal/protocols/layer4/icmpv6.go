package layer4

import (
	"sniffer/internal/model"
)

var icmpv6Types = map[uint8]string {
	1: "Destination Unreachable",
	2: "Packet too big",
	3: "Time exceeded",
	128: "Echo Request",
	129: "Echo Reply",
}

func HandleICMPv6(data []byte, parsedPacket *model.ParsedPacket) (uint16, uint16, []byte) {
	
	typeICMP := data[0]

	if typeString, ok := icmpv6Types[typeICMP]; ok {

		parsedPacket.Infos = typeString		

	} else {
		parsedPacket.Infos = "Unknown Type"
	}

	parsedPacket.Protocol = "ICMPv6"

	return 0, 0, nil
}