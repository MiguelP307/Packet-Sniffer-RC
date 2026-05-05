package layer7

import "sniffer/internal/model"


type HTTPS struct{}

func (h *HTTPS) LayerType() string {
	return "Layer 7"
}

func (h *HTTPS) ProtocolType() string {
	return "HTTPS"
}

func (h *HTTPS) View() []string {
	return []string{
		
	}
}

func HandleHTTPS(data []byte, parsedPacket *model.ParsedPacket) {

	https := &HTTPS{}

	parsedPacket.Layers = append(parsedPacket.Layers, https)

}
