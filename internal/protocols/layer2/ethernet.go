package layer2

import (
	"encoding/binary"
	"fmt"
	"sniffer/internal/model"
	"sniffer/internal/protocols/layer3"
	"sniffer/internal/view"
)


type Ethernet struct {
	SrcMAC string
	DstMAC string
	Type uint16
}

func (e *Ethernet) LayerType() string {
	return "Layer 2"
}

func (e *Ethernet) ProtocolType() string {
	return "Ethernet"
}

func (e *Ethernet) View() []string{
	return []string{
		fmt.Sprintf("Source MAC: %s", e.SrcMAC),
		fmt.Sprintf("Destination MAC: %s", e.DstMAC),
		fmt.Sprintf("Type: %s", view.FormatWithMap16(e.Type,layer3.Protocols)),
	}
}

func HandleEthernet(data []byte, parsedPacket *model.ParsedPacket) (uint16, []byte) {
	
	srcMac := view.FormatMAC(data[0:6])
	dstMac := view.FormatMAC(data[6:12])

	ethType := binary.BigEndian.Uint16(data[12:14])

	ethernet := &Ethernet{
		SrcMAC: srcMac,
		DstMAC: dstMac,
		Type: ethType,
	}

	parsedPacket.Layers = append(parsedPacket.Layers, ethernet)

	return ethType, data[14:]
}


