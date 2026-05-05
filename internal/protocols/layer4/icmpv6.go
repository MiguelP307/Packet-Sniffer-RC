package layer4

import (
	"encoding/binary"
	"fmt"
	"sniffer/internal/model"
	"sniffer/internal/view"
)

var Icmpv6Types = map[uint8]string {
	1: "Destination Unreachable",
	2: "Packet too big",
	3: "Time exceeded",
	128: "Echo Request",
	129: "Echo Reply",
}

type ICMPv6 struct {
	Type uint8
	Code uint8
	CheckSum uint16
}

func (i *ICMPv6) LayerType() string {
	return "Layer 4"
}

func (i *ICMPv6) ProtocolType() string {
	return "ICMPv6"
}

func (i *ICMPv6) View() []string {
	return []string{
		
		fmt.Sprintf("Type: %s", view.FormatWithMap8(i.Type, Icmpv6Types)),
		fmt.Sprintf("Code: %d", i.Code),
		fmt.Sprintf("Checksum: %d", i.CheckSum),
 	}	
}

func HandleICMPv6(data []byte, parsedPacket *model.ParsedPacket) (uint16, uint16, []byte) {
	
	typeICMP := data[0]
	code := data[1]
	checkSum := binary.BigEndian.Uint16(data[2:4])
	
	icmpv6 := &ICMPv6{
		Type: typeICMP, 
		Code: code, 
		CheckSum: uint16(checkSum),
	}

	parsedPacket.Layers = append(parsedPacket.Layers, icmpv6)

	return 0, 0, nil
}