package layer7

import "sniffer/internal/model"

type L7Handler func(data []byte, parsedPacket *model.ParsedPacket)

var Handlers = map[uint16]L7Handler{
	/* 53: HandleDNS,
	67: HandleDHCP,
	68: HandleDHCP, */
	80: HandleHTTP,
	443: HandleHTTPS,
}