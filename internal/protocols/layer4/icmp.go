package layer4

import (
	"encoding/binary"
	"fmt"
	"sniffer/internal/model"
	"sniffer/internal/view"
)

var Icmpv4Types = map[uint8]string {
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

type ICMP struct {
	Type uint8
	Code uint8
	CheckSum uint16
}

func (i *ICMP) LayerType() string {
	return "Layer 4"
}
 
func (i *ICMP) ProtocolType() string {
	return "ICMP"
}

func (i *ICMP) View() []string {
	return []string{
		
		fmt.Sprintf("Type: %s", view.FormatWithMap8(i.Type, Icmpv4Types)),
		fmt.Sprintf("Code: %d", i.Code),
		fmt.Sprintf("Checksum: %d", i.CheckSum),
 	}	
}

func HandleICMP(data []byte, parsedPacket *model.ParsedPacket) (uint16, uint16, []byte) {
	
	typeICMP := data[0]
	code := data[1]
	checkSum := binary.BigEndian.Uint16(data[2:4])
	
	icmp := &ICMP{
		Type: typeICMP, 
		Code: code, 
		CheckSum: uint16(checkSum),
	}

	parsedPacket.Layers = append(parsedPacket.Layers, icmp)

	return 0, 0, nil
}