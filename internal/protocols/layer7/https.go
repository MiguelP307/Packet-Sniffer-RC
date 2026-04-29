package layer7

import "sniffer/internal/model"


func HandleHTTPS(data []byte, parsedPacket *model.ParsedPacket){

	parsedPacket.Protocol = "HTTPS"

}