package layer3

import (
	"encoding/binary"
	"fmt"
	"net"
	"sniffer/internal/model"
)

type IPv4 struct {

	Version uint8
	HeaderLength uint8
	TotalLength uint16

	Identification uint16
	
	//Flags 3-bit
	ReservedBit bool
	NotFragment bool
	MoreFragments bool

	FragmentOffset uint16

	TTL uint8
	Protocol uint8
	HeaderCheckSum uint16

	SrcIP string
	DstIP string

}

func (i *IPv4) LayerType() string {
	return "Layer 3"
}

func (i *IPv4) ProtocolType() string {
	return "IPv4"
}

func (i *IPv4) View() []string {
	
	return []string{
		fmt.Sprintf("Version: %d", i.Version),
		fmt.Sprintf("Header Length: %d", i.HeaderLength),
		fmt.Sprintf("Total Length: %d", i.TotalLength),
		fmt.Sprintf("Identification: %d", i.Identification),
		fmt.Sprintf("Flag: Reserved: %t", i.ReservedBit),
		fmt.Sprintf("Flag: Don't Fragment: %t",i.NotFragment),
		fmt.Sprintf("Flag: More Fragments: %t",i.MoreFragments),
		fmt.Sprintf("Fragment Offset: %d", i.FragmentOffset),
		fmt.Sprintf("TTL: %d", i.TTL),
		fmt.Sprintf("Protocol: %d", i.Protocol),
		fmt.Sprintf("Header Checksum: %d", i.HeaderCheckSum),
		fmt.Sprintf("Source IP: %s", i.SrcIP),
		fmt.Sprintf("Destination IP: %s", i.DstIP),
	}
}

func HandleIPv4(data []byte, parsedPacket *model.ParsedPacket) (uint8, []byte){

	// Get header length
	fstByte := data[0]
	version := fstByte >> 4
	headerLen := (fstByte & 0x0F) * 4

	totalLength := binary.BigEndian.Uint16(data[2:4])
	id := binary.BigEndian.Uint16(data[4:6])

	flagsFragment := binary.BigEndian.Uint16(data[6:8])

	rbFlag := (flagsFragment >> 15) & 0x01
	nfFlag := (flagsFragment >> 14) & 0x01
	mfFlag := (flagsFragment >> 13) & 0x01

	offset := flagsFragment & 0x1FFF

	ttl := data[8]
	protocol := data[9]

	checkSum := binary.BigEndian.Uint16(data[10:12])

	srcIP := getIPv4(data[12:16])
	dstIP := getIPv4(data[16:20])

	ipv4 := &IPv4{
		Version: version,
		HeaderLength: headerLen,
		TotalLength: totalLength,
		Identification: id,

		//Flags 3-bit
		ReservedBit: rbFlag == 1,
		NotFragment: nfFlag == 1,
		MoreFragments: mfFlag == 1,

		FragmentOffset: offset,
		TTL: ttl,
		Protocol: protocol,
		HeaderCheckSum: checkSum,

		SrcIP: srcIP,
		DstIP: dstIP,
	}

	parsedPacket.Layers = append(parsedPacket.Layers, ipv4)

	return protocol, data[headerLen:]
}


func getIPv4(data []byte) (string) {
	// Data will always be 4 bytes long, Uint32
	return net.IP(data).String()
}