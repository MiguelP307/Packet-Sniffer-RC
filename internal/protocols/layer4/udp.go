package layer4

import (
	"encoding/binary"
	"sniffer/internal/model"
	"strconv"
)


func HandleUDP(data []byte, parsedPacket *model.ParsedPacket) (uint16, uint16, []byte) {

	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])

	parsedPacket.SrcPort =  strconv.Itoa(int(srcPort))
	parsedPacket.DstPort =  strconv.Itoa(int(dstPort))

	parsedPacket.Protocol = "UDP"

	payload := data[8:]

	return srcPort, dstPort, payload

}