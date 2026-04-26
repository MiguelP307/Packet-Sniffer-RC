package parser

import (
	"fmt"
	"sniffer/internal/model"
	"sniffer/internal/protocols/layer2"
	"sniffer/internal/protocols/layer3"
	"sniffer/internal/protocols/layer4"
	"sniffer/internal/protocols/layer7"

	"github.com/google/gopacket"
)

<<<<<<< HEAD
func Parse(packet gopacket.Packet, iface string) {
=======

func Parse(packet gopacket.Packet, iface string){
>>>>>>> 0286b4ff7ea493a743249f08b95da76d452cd6b4

	//Gets the full packet as raw bytes
	data := packet.Data()

	//
	newParsedPacket := newParsedPacket(packet, iface)

	ethType, payload := layer2.HandleEthernet(data)

	parseL3(ethType, payload, newParsedPacket)
}

<<<<<<< HEAD
func newParsedPacket(packet gopacket.Packet, iface string) model.ParsedPacket {
	return model.ParsedPacket{
=======

func newParsedPacket(packet gopacket.Packet, iface string) (*model.ParsedPacket){
	return &model.ParsedPacket{
>>>>>>> 0286b4ff7ea493a743249f08b95da76d452cd6b4
		Timestamp: packet.Metadata().Timestamp.String(),
		Interface: iface,
	}
}

func parseL3(ethType uint16, data []byte, newParsedPacket *model.ParsedPacket) {

<<<<<<< HEAD
	switch ethType {
	case 0x0800:
		fmt.Println("IPv4")

		// Cut the packet to only pass the payload, (Ethernet layer its 12 bytes)
		protL4, payload := layer3.HandleIPv4(data, &newParsedPacket)

		fmt.Println(newParsedPacket)

		parseL4(protL4, payload, &newParsedPacket)

	case 0x0806:

		fmt.Println("ARP")
		layer3.HandleARP(data, &newParsedPacket)
		fmt.Println(newParsedPacket)

	case 0x86DD:
		fmt.Println("IPv6")

	default:
		fmt.Println("Unknown Protocol on Layer 3")
=======
	if handler, ok := layer3.Handlers[ethType]; ok {
		protL4, payload := handler(data, newParsedPacket)

		parseL4(protL4, payload, newParsedPacket)
	}

	newParsedPacket.Infos = "Unknown L3"
}

func parseL4(protocol uint8, data []byte, newParsedPacket *model.ParsedPacket) {

	if handler, ok := layer4.Handlers[protocol]; ok {
		srcPort, dstPort, payload := handler(data, newParsedPacket)

		if payload != nil {
			parseL7(srcPort, dstPort, payload, newParsedPacket)
			return
		}

		fmt.Println(newParsedPacket)

		return
>>>>>>> 0286b4ff7ea493a743249f08b95da76d452cd6b4
	}
 
	newParsedPacket.Infos = "Unknown L4"
}

func parseL7(srcPort uint16, dstPort uint16, data []byte, newParsedPacket *model.ParsedPacket) {

	if handler, ok := layer7.Handlers[srcPort]; ok {
		handler(data, newParsedPacket)
		fmt.Println(newParsedPacket)
		return
	}

<<<<<<< HEAD
	case 1:
	// ICMP

	case 6:
	// TCP

	case 17:
	// UDP

	case 58:
	//ICMPv6

	default:
	}
}
=======
	if handler, ok := layer7.Handlers[dstPort]; ok {
		handler(data, newParsedPacket)
		fmt.Println(newParsedPacket)
		return
	}

	newParsedPacket.Infos = "Unknown L7"

}
>>>>>>> 0286b4ff7ea493a743249f08b95da76d452cd6b4
