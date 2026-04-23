package layer4

import (
	"encoding/binary"
	"sniffer/internal/model"
	"strconv"
)


func HandleTCP(data []byte, parsedPacket *model.ParsedPacket) (uint16, uint16, []byte){

	dataOffset := (data[12] >> 4) & 0x0F
	headerLen := int(dataOffset) * 4

	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])

	parsedPacket.SrcPort =  strconv.Itoa(int(srcPort))
	parsedPacket.DstPort =  strconv.Itoa(int(dstPort))

	parsedPacket.Protocol = "TCP"


	// Flags
	flags := data[13]

	
	switch flags {
	case 0x02:
		parsedPacket.Infos = "TCP SYN (Connection Start)"

	case 0x12:
		parsedPacket.Infos = "TCP SYN-ACK"

	case 0x01:
		parsedPacket.Infos = "TCP FYN"
	
	case 0x11:
		parsedPacket.Infos = "TCP ACK-FIN"

	case 0x10:
		parsedPacket.Infos = "TCP ACK"

	default:
		parsedPacket.Infos = "TCP Other"
	}

	payload := data[headerLen:]

	return srcPort, dstPort, payload
}
