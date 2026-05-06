package model

import "time"

type ParsedPacket struct {

	Timestamp time.Time
	Interface string
	Length int
	Infos string

	Layers[]Layer

}

type Layer interface{
	LayerType() string
	ProtocolType() string
	View() []string
}

func getProtocol(p ParsedPacket) string {
	if len(p.Layers) == 0 {
		return "Unknown"
	}
	return p.Layers[len(p.Layers)-1].ProtocolType()
}

