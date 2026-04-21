package parser

import (
	"fmt"
	"sniffer/internal/model"
	"sniffer/internal/protocols/layer2"
	"sniffer/internal/protocols/layer3"

	"github.com/google/gopacket"
)

func Parse(packet gopacket.Packet, iface string){

	//Gets the full packet as raw bytes
	data := packet.Data()

	// 
	newParsedPacket := newParsedPacket(packet, iface)

	ethType, payload := layer2.HandleEthernet(data)
	
	parseL3(ethType, payload, newParsedPacket)
}


func newParsedPacket(packet gopacket.Packet, iface string) (model.ParsedPacket){
	return model.ParsedPacket{
		Timestamp: packet.Metadata().Timestamp.String(),
		Interface: iface,
	}
}

func parseL3(ethType uint16, data []byte, newParsedPacket model.ParsedPacket) {

	switch ethType {
		case 0x0800:
			fmt.Println("IPv4")

			// Cut the packet to only pass the payload, (Ethernet layer its 12 bytes)
			protL4, payload := layer3.HandleIPv4(data, &newParsedPacket)
			
			fmt.Println(newParsedPacket)

			parseL4(protL4, payload, &newParsedPacket)

		case 0x0806:
			fmt.Println("ARP")

		case 0x86DD:
			fmt.Println("IPv6")


		default:
			fmt.Println("Unknown Protocol on Layer 3")
	}
}

func parseL4(protocol uint8, data []byte, newParsedPacket *model.ParsedPacket) {

	switch protocol {

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