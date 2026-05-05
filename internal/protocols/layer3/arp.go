package layer3

import (
	"encoding/binary"
	"fmt"
	"net"
	"sniffer/internal/model"
	"sniffer/internal/view"
)

var opcodes = map[uint16]string {
	1: "Request",
	2: "Reply",
}

type ARP struct {

	ProtType uint16
	HardLen uint8
	ProtLen uint8
	Opcode uint16
	
	SrcMAC string
	SrcIP string
	DstMAC string
	DstIP string

}

func (a *ARP) LayerType() string {
	return "Layer 3"
}

func (a *ARP) ProtocolType() string{
	return "ARP"
}

func (a *ARP) View() []string {
	
	return []string{
		fmt.Sprintf("Protocol: %d", a.ProtType),
		fmt.Sprintf("Hardware Length: %d", a.HardLen),
		fmt.Sprintf("Protocol Length: %d", a.ProtLen),
		fmt.Sprintf("Opcode: %s", view.FormatWithMap16(a.Opcode,opcodes)),
		fmt.Sprintf("Source MAC: %s", a.SrcMAC),
		fmt.Sprintf("Source IP: %s", a.SrcIP),
		fmt.Sprintf("Destination MAC: %s", a.DstMAC),
		fmt.Sprintf("Destination IP: %s", a.DstIP),
	}
}

func HandleARP(data []byte, parsedPacket *model.ParsedPacket) (uint8, []byte) {

	protocolType := binary.BigEndian.Uint16(data[2:4])
	hardLen := data[4]
	protLen := data[5]
	opcode := binary.BigEndian.Uint16(data[6:8])

	senderMAC := view.FormatMAC(data[8:14])
	senderIP := net.IP(data[14:18]).String()

	targetMAC := view.FormatMAC(data[18:24])
	targetIP := net.IP(data[24:28]).String()

	arp := &ARP{
		ProtType: protocolType,
		HardLen: hardLen,
		ProtLen: protLen,
		Opcode: opcode,
		SrcMAC:   senderMAC,
		SrcIP:    senderIP,
		DstMAC:   targetMAC,
		DstIP:    targetIP,
	}
	
	parsedPacket.Layers = append(parsedPacket.Layers, arp)

	return 0, nil

}

