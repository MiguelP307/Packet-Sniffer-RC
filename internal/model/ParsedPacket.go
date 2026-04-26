package model

import "fmt"

type ParsedPacket struct {

	Timestamp string
	Interface string

	Protocol string
	
	SrcMAC string 
	DstMAC string
	
	SrcIP string
	DstIP string

	SrcPort string
	DstPort string
	
	Length int
	
	Infos string
}


// Fazer dps mais bom melhor lindo

func (p ParsedPacket) String() string {
	return fmt.Sprintf(
		`--- Packet ---
Time:      %s
Iface:     %s
Protocol:  %s
Length:    %d bytes

Src MAC:   %s
Dst MAC:   %s

Src IP:    %s
Dst IP:    %s

Src Port:    %s
Dst Port:    %s

Info:      %s
--------------`,
		p.Timestamp,
		p.Interface,
		p.Protocol,
		p.Length,
		p.SrcMAC,
		p.DstMAC,
		p.SrcIP,
		p.DstIP,
		p.SrcPort,
		p.DstPort,
		p.Infos,
	)
}