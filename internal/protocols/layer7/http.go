package layer7

import "sniffer/internal/model"

func HandleHTTP(data []byte, parsedPacket *model.ParsedPacket) {

	parsedPacket.Protocol = "HTTP"
	parsedPacket.Infos = "HTTP packet"

}
