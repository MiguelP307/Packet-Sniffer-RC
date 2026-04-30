package layer7

import "sniffer/internal/model"

func HandleDHCP(data []byte, parsedPacket *model.ParsedPacket) {
	parsedPacket.Protocol = "DHCP"
	parsedPacket.Infos = "DHCP packet"
}
