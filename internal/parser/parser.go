package parser

import (
	//"fmt"
	"fmt"
	"sniffer/internal/model"
	"sniffer/internal/protocols/layer2"
	"sniffer/internal/protocols/layer3"
	"sniffer/internal/protocols/layer4"
	"sniffer/internal/protocols/layer7"
	"sniffer/internal/view"

	"github.com/google/gopacket"
)

func Parse(packet gopacket.Packet, iface string) model.ParsedPacket {

	data := packet.Data()

	newParsedPacket := newParsedPacket(packet, iface)

	ethType, payload := layer2.HandleEthernet(data, newParsedPacket)

	parseL3(ethType, payload, newParsedPacket)

	newParsedPacket.Infos = BuildInfo(*newParsedPacket)

	return *newParsedPacket
}



func newParsedPacket(packet gopacket.Packet, iface string) (*model.ParsedPacket){

	return &model.ParsedPacket{
		Timestamp: packet.Metadata().Timestamp.String(),
		Interface: iface,
		Length: int(len(packet.Data())),
		Layers: []model.Layer{},
	}
}

func parseL3(ethType uint16, data []byte, newParsedPacket *model.ParsedPacket){


	if handler, ok := layer3.Handlers[ethType]; ok {
		protL4, payload := handler(data, newParsedPacket)

		if payload != nil {
			parseL4(protL4, payload, newParsedPacket)
			return
		}

		return
	}

}

func parseL4(protocol uint8, data []byte, newParsedPacket *model.ParsedPacket) {

	if handler, ok := layer4.Handlers[protocol]; ok {
		srcPort, dstPort, payload := handler(data, newParsedPacket)

		if payload != nil {
			parseL7(srcPort, dstPort, payload, newParsedPacket)
			return
		}

		return
	}
 
}

func parseL7(srcPort uint16, dstPort uint16, data []byte, newParsedPacket *model.ParsedPacket) {

	if handler, ok := layer7.Handlers[srcPort]; ok {
		handler(data, newParsedPacket)
		return
	}


	if handler, ok := layer7.Handlers[dstPort]; ok {
		handler(data, newParsedPacket)
		return
	}

}



// -------------- Function that build little packet description --------------

func BuildInfo(p model.ParsedPacket) string {

	var srcIP, dstIP string

	// First pass: get IPs
	for _, l := range p.Layers {

		switch v := l.(type) {

		case *layer3.IPv4:

			srcIP = v.SrcIP
			dstIP = v.DstIP
		case *layer3.IPv6:

			srcIP = v.SrcIP
			dstIP = v.DstIP
		}
	}

	// Second pass: top-down logic
	for i := len(p.Layers) - 1; i >= 0; i-- {
		switch v := p.Layers[i].(type) {

		/* ---------- HTTP ---------- */
		case *layer7.HTTP_Request:
			return fmt.Sprintf("%s %s", v.Method, v.URI)

		case *layer7.HTTP_Response:
			return fmt.Sprintf("%s %s", v.StatusCode, v.StatusText)

		/* ---------- TCP ---------- */
		case *layer4.TCP:
			return fmt.Sprintf("%s:%s → %s:%s",
				srcIP, v.SrcPort,
				dstIP, v.DstPort,
			)

		/* ---------- UDP ---------- */
		case *layer4.UDP:
			return fmt.Sprintf("%s:%s → %s:%s",
				srcIP, v.SrcPort,
				dstIP, v.DstPort,
			)

		/* ---------- ICMP ---------- */
		case *layer4.ICMP:
			return view.FormatWithMap8(v.Type, layer4.Icmpv4Types)

		/* ---------- ICMPv6 ---------- */
		case *layer4.ICMPv6:
			return view.FormatWithMap8	(v.Type, layer4.Icmpv6Types)

		/* ---------- ARP ---------- */
		case *layer3.ARP:
			switch v.Opcode {
			case 1:
				return fmt.Sprintf("Who has %s? Tell %s", v.DstIP, v.SrcIP)
			case 2:
				return fmt.Sprintf("%s is at %s", v.SrcIP, v.SrcMAC)
			}
			return "ARP"

		/* ---------- IP fallback ---------- */
		case *layer3.IPv4, *layer3.IPv6:
			if srcIP != "" && dstIP != "" {
				return fmt.Sprintf("%s → %s", srcIP, dstIP)
			}
		}
	}

	return "Unknown"
}

