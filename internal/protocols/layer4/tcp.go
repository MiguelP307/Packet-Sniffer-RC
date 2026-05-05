package layer4

import (
	"encoding/binary"
	"fmt"
	"sniffer/internal/model"
	"strconv"
)

type TCP struct {

	SrcPort string
	DstPort string

	SeqNumber uint32

	AckNumber uint32

	DataOffset uint8
	
	//Flags
	AckFlag bool
	SynFlag bool
	FinFlag bool

}

func (t *TCP) LayerType() string {
	return "Layer 4"
}

func (t *TCP) ProtocolType() string{
	return "TCP"
}

func (t *TCP) View() []string {

	return []string{
		fmt.Sprintf("Source Port: %s", t.SrcPort),
		fmt.Sprintf("Destination Port: %s", t.DstPort),
		fmt.Sprintf("Sequence Number (Raw): %d", t.SeqNumber),
		fmt.Sprintf("Acknowledgment Number (Raw): %d", t.AckNumber),
		fmt.Sprintf("Data Offset: %d", t.DataOffset),
		fmt.Sprintf("Flags: SYN=%t, ACK=%t, FIN=%t", t.SynFlag, t.AckFlag, t.FinFlag),
	}
}

func HandleTCP(data []byte, parsedPacket *model.ParsedPacket) (uint16, uint16, []byte){

	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])

	parsedSrcPort :=  strconv.Itoa(int(srcPort))
	parsedDstPort :=  strconv.Itoa(int(dstPort))

	seqNum := binary.BigEndian.Uint32(data[4:8])
	ackNum := binary.BigEndian.Uint32(data[8:12])

	dataOffset := (data[12] >> 4) & 0x0F
	headerLen := int(dataOffset) * 4

	flags := data[13]

	ackF := flags & 0x10
	synF := flags & 0x02
	finF := flags & 0x01


	tcp := &TCP{

		SrcPort: parsedSrcPort,
		DstPort: parsedDstPort,

		SeqNumber: seqNum,

		AckNumber: ackNum,

		DataOffset: dataOffset,
		
		//Flags
		AckFlag: ackF == 1,
		SynFlag: synF == 1,
		FinFlag: finF == 1,
	}
	
	parsedPacket.Layers = append(parsedPacket.Layers, tcp)

	payload := data[headerLen:]

	return srcPort, dstPort, payload
}
