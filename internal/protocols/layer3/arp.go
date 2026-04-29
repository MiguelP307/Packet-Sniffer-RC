package layer3

import (
	"encoding/binary"
	"fmt"
	"net"
	"sniffer/internal/model"
)

func HandleARP(data []byte, parsedPacket *model.ParsedPacket) {

	hardwareType := binary.BigEndian.Uint16(data[0:2])
	protocolType := binary.BigEndian.Uint16(data[2:4])
	opcode := binary.BigEndian.Uint16(data[6:8])

	senderMAC := formatMAC(data[8:14])
	senderIP := net.IP(data[14:18]).String()

	targetMAC := formatMAC(data[18:24])
	targetIP := net.IP(data[24:28]).String()

	parsedPacket.Protocol = "ARP"
	parsedPacket.SrcMAC = senderMAC
	parsedPacket.DstMAC = targetMAC
	parsedPacket.SrcIP = senderIP
	parsedPacket.DstIP = targetIP

	var op string
	op = "Unknown"
	if opcode == 1 {
		op = "Request"
	} else if opcode == 2 {
		op = "Reply"
	}

	parsedPacket.Infos = fmt.Sprintf("%s | %s → %s (htype=%d ptype=0x%04x)",
		op,
		senderIP,
		targetIP,
		hardwareType,
		protocolType,
	)

}

func formatMAC(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5])
}
