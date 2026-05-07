package layer3

import (
	"encoding/binary"
	"fmt"
	"net"
	"sniffer/internal/model"
	"sniffer/internal/protocols/layer4"
	"sniffer/internal/view"
)

var TraffiClasses = map[uint8]string{
	0: "No Specific traffic",
	1: "Background data",
	2: "Unattended data traffic",
	3: "Reserved",
	4: "Attended bulk data traffic",
	5: "Reserver",
	6: "Interactive traffic",
	7: "Control traffic",
}

type IPv6 struct {

	Version uint8
	TrafficClass uint8
	FlowLabel uint32

	PayloadLength uint16
	NextHeader uint8
	HopLimit uint8

	SrcIP string
	DstIP string

}

func (i *IPv6) LayerType() string {
	return "Layer 3"
}

func (i *IPv6) ProtocolType() string {
	return "IPv6"
}

func (i *IPv6) View() []string{
	
	return []string{
		fmt.Sprintf("Version: %d", i.Version),
		fmt.Sprintf("Traffic Class: %d", view.FormatWithMap8(i.TrafficClass,TraffiClasses)),
		fmt.Sprintf("Flow Label: %d", i.FlowLabel),
		fmt.Sprintf("Payload Length: %d", i.PayloadLength),
		fmt.Sprintf("Next Header: %t", view.FormatWithMap8(i.NextHeader,layer4.Protocols)),
		fmt.Sprintf("Hop Limit: %t",i.HopLimit),
		fmt.Sprintf("Source IP: %s", i.SrcIP),
		fmt.Sprintf("Destination IP: %s", i.DstIP),
	}
}

func HandleIPv6(data []byte, parsedPacket *model.ParsedPacket) (uint8, []byte) {
	
	

	firstRow := binary.BigEndian.Uint32(data[0:4])

	version := (firstRow >> 28) & 0x0F
	trafficClass := (firstRow >> 20) & 0xFF
	flowLabel := firstRow & 0x000FFFFF

	payloadLength := binary.BigEndian.Uint16(data[4:6])
	nextHeader := data[6]
	hopLimit := data[7]

	IPv6HeaderLen := 40
	offset := IPv6HeaderLen	

	headerLen := 0
	
	for isExtensionHeader(nextHeader){

		nextExtHeader := data[offset:]

		switch(nextHeader){
		case 0:
		case 43:
		case 60:
			headerLen = (int(nextExtHeader[1]) + 1) * 8			
	
		case 44:
			headerLen = 8

		case 51:
			headerLen = (int(nextExtHeader[1]) + 1) * 4
	
		default:
			fmt.Printf("Unknown Extension Header: %d\n" , nextHeader)
			
			return 0, []byte{}
		}
		

		nextHeader = nextExtHeader[0]
		offset += headerLen
	}


	srcIP := getIPv6(data[8:24])
	dstIP := getIPv6(data[24:40])

	ipv6 := &IPv6{

		Version: uint8(version),
		TrafficClass: uint8(trafficClass),
		FlowLabel: flowLabel,

		PayloadLength: payloadLength,
		NextHeader: nextHeader,
		HopLimit: hopLimit,

		SrcIP: srcIP,
		DstIP: dstIP,

	}

	parsedPacket.Layers = append(parsedPacket.Layers, ipv6)

	return nextHeader, data[offset:]
}


func isExtensionHeader(headerT byte) bool {
	if headerT == 1 || headerT == 6 || headerT == 17 || headerT == 58 {
		return false
	} else {
		return true
	}
}

func getIPv6(data []byte) string {
	return net.IP(data).String()
}