package layer3

import (
	"fmt"
	"net"
	"sniffer/internal/model"
)

func HandleIPv6(data []byte, parsedPacket *model.ParsedPacket) (uint8, []byte) {
	
	nextHeader := data[6]
	IPv6HeaderLen := 40
	offset := IPv6HeaderLen	

	headerLen := 0
	
	// Check if the IPv6 has extension packets
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

	parsedPacket.Protocol = "IPv6"

	parsedPacket.SrcIP = getIPv6(data[8:24])
	parsedPacket.DstIP = getIPv6(data[24:40])

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