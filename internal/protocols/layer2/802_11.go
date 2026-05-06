package layer2

import (
	"encoding/binary"
	"fmt"
	"sniffer/internal/model"
	"sniffer/internal/view"
)


type WiFi struct {
	FrameControl uint16

	Type    uint8
	Subtype uint8

	ToDS    bool
	FromDS  bool
	Retry   bool
	Protected bool

	Duration uint16

	DstMAC string
	SrcMAC string
	BSSID  string

	SeqNum uint16

	QoS uint8
}


func (w *WiFi) LayerType() string {
	return "Layer 2"
}

func (w *WiFi) ProtocolType() string {
	return "WiFi"
}

func (w *WiFi) View() []string {

	frameTypeStr := map[uint8]string{
		0: "Management",
		1: "Control",
		2: "Data",
	}

	var flags []string

	if w.ToDS {
		flags = append(flags, "ToDS")
	}
	if w.FromDS {
		flags = append(flags, "FromDS")
	}
	if w.Retry {
		flags = append(flags, "Retry")
	}
	if w.Protected {
		flags = append(flags, "Protected")
	}

	flagStr := "None"
	if len(flags) > 0 {
		flagStr = fmt.Sprintf("%v", flags)
	}

	return []string{
		fmt.Sprintf("Frame Control: 0x%04x", w.FrameControl),
		fmt.Sprintf("Type: %s (%d)", frameTypeStr[w.Type], w.Type),
		fmt.Sprintf("Subtype: %d", w.Subtype),

		fmt.Sprintf("Flags: %s", flagStr),

		fmt.Sprintf("Duration: %d", w.Duration),

		fmt.Sprintf("Source MAC: %s", w.SrcMAC),
		fmt.Sprintf("Destination MAC: %s", w.DstMAC),
		fmt.Sprintf("BSSID: %s", w.BSSID),

		fmt.Sprintf("Sequence Number: %d", w.SeqNum),

		fmt.Sprintf("QoS: %d", w.QoS),
	}
}

func HandleWiFi(data []byte, parsedPacket *model.ParsedPacket) (uint16, []byte) {

	if len(data) < 24 {
		return 0, nil
	}

	frameControl := binary.LittleEndian.Uint16(data[0:2])

	frameType := uint8((frameControl >> 2) & 0x3)
	subtype := uint8((frameControl >> 4) & 0xF)

	toDS := frameControl & 0x0100 != 0
	fromDS := frameControl & 0x0200 != 0
	retry := frameControl & 0x0800 != 0
	protected := frameControl & 0x4000 != 0

	duration := binary.LittleEndian.Uint16(data[2:4])

	dstMAC := view.FormatMAC(data[4:10])
	srcMAC := view.FormatMAC(data[10:16])
	bssid := view.FormatMAC(data[16:22])

	seqCtrl := binary.LittleEndian.Uint16(data[22:24])
	seqNum := seqCtrl >> 4

	headerLen := 24

	wifi := &WiFi{
		FrameControl: frameControl,
		Type:         frameType,
		Subtype:      subtype,
		ToDS:         toDS,
		FromDS:       fromDS,
		Retry:        retry,
		Protected:    protected,
		Duration:     duration,
		DstMAC:       dstMAC,
		SrcMAC:       srcMAC,
		BSSID:        bssid,
		SeqNum:       seqNum,
	}

	parsedPacket.Layers = append(parsedPacket.Layers, wifi)

	return 0, data[headerLen:]
}


