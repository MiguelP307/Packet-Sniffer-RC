package flow

import (
	"sniffer/internal/model"
	"sniffer/internal/protocols/layer3"
	"sniffer/internal/protocols/layer4"
)

type FlowData struct {
	SrcIP   string
	DstIP   string
	SrcPort string
	DstPort string
	Protocol string

	TCP *layer4.TCP
}

func ExtractFlowData(p model.ParsedPacket) *FlowData {

	data := &FlowData{}

	// --- Extract IP ---
	for _, l := range p.Layers {
		switch v := l.(type) {

		case *layer3.IPv4:
			data.SrcIP = v.SrcIP
			data.DstIP = v.DstIP

		case *layer3.IPv6:
			data.SrcIP = v.SrcIP
			data.DstIP = v.DstIP
		}
	}

	// --- Extarct transport ---
	for i := len(p.Layers) - 1; i >= 0; i-- {

		switch v := p.Layers[i].(type) {

		case *layer4.TCP:
			data.SrcPort = v.SrcPort
			data.DstPort = v.DstPort
			data.Protocol = "TCP"
			data.TCP = v
			return data

		case *layer4.UDP:
			data.SrcPort = v.SrcPort
			data.DstPort = v.DstPort
			data.Protocol = "UDP"
			return data
		}
	}

	return data
}