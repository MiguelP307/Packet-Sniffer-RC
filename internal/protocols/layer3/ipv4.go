package layer3

import (
	"sniffer/internal/model"
	"net"
)

func HandleIPv4(data []byte, parsedPacket *model.ParsedPacket) (uint8, []byte){

	// Get header length
	fstByte := data[0]
	headerLen := int(fstByte & 0x0F) * 4

	protocol := data[9]

	parsedPacket.SrcIP = getIP(data[12:16])
	parsedPacket.DstIP = getIP(data[16:20])

	parsedPacket.Protocol = "IPv4"

	return protocol, data[headerLen:]
}


func getIP(data []byte) (string) {
	// Data will always be 4 bytes long, Uint32
	return net.IP(data).String()
}