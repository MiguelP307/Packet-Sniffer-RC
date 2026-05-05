package layer7

import "sniffer/internal/model"

type DNS struct{}

func (d *DNS) LayerType() string {
	return "Layer 7"
}

func (d *DNS) ProtocolType() string {
	return "DNS"
}

func (d *DNS) View() []string {
	return []string{

	}
}

func HandleDNS(data []byte, parsedPacket *model.ParsedPacket) {

	dns := &DNS{}

	parsedPacket.Layers = append(parsedPacket.Layers, dns)

}
