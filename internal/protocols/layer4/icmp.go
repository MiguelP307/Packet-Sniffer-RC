package layer4

import (
	"sniffer/internal/model"
)

var icmpv4Types = map[uint8]string {
	0: "Echo Reply",
	3: "Destination Unreachable",
	5: "Redirect Message",
	8: "Echo Request",
	9: "Router Advertisement",
	10: "Router Solicitation",
	11: "Time Exceeded",
	12: "Parameter Problem",
	13: "Timestamp",
	14: "Timestamp Reply",
}

func HandleICMP(data []byte, parsedPacket *model.ParsedPacket) (uint16, uint16, []byte) {
	
	typeICMP := data[0]

	if typeString, ok := icmpv4Types[typeICMP]; ok {

		parsedPacket.Infos = typeString		
		
	} else {
		parsedPacket.Infos = "Unknown Type"
	}

	parsedPacket.Protocol = "ICMP"

	return 0, 0, nil
}