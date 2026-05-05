package layer7

import "sniffer/internal/model"

type DHCP struct{}

func (d *DHCP) LayerType() string {
	return "Layer 7"
}

func (d *DHCP) ProtocolType() string {
	return "DHCP"
}

func (d *DHCP) View() []string {
	return []string{
		
	}
}

func HandleDHCP(data []byte, parsedPacket *model.ParsedPacket) {
	
	dhcp := &DHCP{}

	parsedPacket.Layers = append(parsedPacket.Layers, dhcp)
}
