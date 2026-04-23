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


func Parse(packet gopacket.Packet, iface string){

	//Gets the full packet as raw bytes
	data := packet.Data()

	// 
	newParsedPacket := newParsedPacket(packet, iface)

	ethType, payload := layer2.HandleEthernet(data)
	
	parseL3(ethType, payload, newParsedPacket)
}


func newParsedPacket(packet gopacket.Packet, iface string) (*model.ParsedPacket){
	return &model.ParsedPacket{
		Timestamp: packet.Metadata().Timestamp.String(),
		Interface: iface,
	}
}

func parseL3(ethType uint16, data []byte, newParsedPacket *model.ParsedPacket) {

	if handler, ok := layer3.Handlers[ethType]; ok {
		protL4, payload := handler(data, newParsedPacket)

		//fmt.Println(newParsedPacket)

		parseL4(protL4, payload, newParsedPacket)
	}

	newParsedPacket.Infos = "Unknown L3"
}

func parseL4(protocol uint8, data []byte, newParsedPacket *model.ParsedPacket) {

	if handler, ok := layer4.Handlers[protocol]; ok {
		srcPort, dstPort, payload := handler(data, newParsedPacket)
		
		//fmt.Println(newParsedPacket)

		parseL7(srcPort, dstPort, payload, newParsedPacket)

	}

	newParsedPacket.Infos = "Unknown L4"
}

func parseL7(srcPort uint16, dstPort uint16, data []byte, newParsedPacket *model.ParsedPacket) {

	if handler, ok := layer7.Handlers[srcPort]; ok {
		handler(data, newParsedPacket)
		fmt.Println(newParsedPacket)
		return
	}

	if handler, ok := layer7.Handlers[dstPort]; ok {
		handler(data, newParsedPacket)
		fmt.Println(newParsedPacket)
		return
	}

	newParsedPacket.Infos = "Unknown L7"

	fmt.Print()
}