package layer7

import "sniffer/internal/model"


func HandleDNS(data []byte, parsedPacket *model.ParsedPacket){

	parsedPacket.Protocol = "DNS"

}