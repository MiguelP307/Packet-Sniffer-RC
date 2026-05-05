package layer4

import (
	"encoding/binary"
	"fmt"
	"sniffer/internal/model"
	"strconv"
)

type UDP struct {

	SrcPort string
	DstPort string

	TotalLength uint16
}

func (u *UDP) LayerType() string {
	return "Layer 4"
}

func (u *UDP) ProtocolType() string{
	return "UDP"
}

func (u *UDP) View() []string {
	return []string{
		fmt.Sprintf("Source Port: %s", u.SrcPort),
		fmt.Sprintf("Destination Port: %s", u.DstPort),
		fmt.Sprintf("Total Length: %d", u.TotalLength),	
	}
}

func HandleUDP(data []byte, parsedPacket *model.ParsedPacket) (uint16, uint16, []byte) {

	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])

	parsedSrcPort :=  strconv.Itoa(int(srcPort))
	parsedDstPort :=  strconv.Itoa(int(dstPort))

	tLen := binary.BigEndian.Uint16(data[4:6])

	udp := &UDP{

		SrcPort: parsedSrcPort,
		DstPort: parsedDstPort,
		TotalLength: tLen,
	}

	parsedPacket.Layers = append(parsedPacket.Layers, udp)

	payload := data[8:]

	return srcPort, dstPort, payload

}