package view

import (
	"fmt"
	"sniffer/internal/model"
)

func RenderPacket(p model.ParsedPacket) []string {
	var output []string

	// Packet summary
	output = append(output,
		fmt.Sprintf("Timestamp: %s", p.Timestamp),
		fmt.Sprintf("Interface: %s", p.Interface),
		fmt.Sprintf("Length: %d", p.Length),
		//fmt.Sprintf("Info: %s", p.Infos),
		"",
	)

	// Layers
	for _, layer := range p.Layers {
		header := fmt.Sprintf("%s: %s",
			layer.LayerType(),
			layer.ProtocolType(),
		)

		output = append(output, header)

		for _, line := range layer.View() {
			output = append(output, "  "+line)
		}

		output = append(output, "") // spacing
	}

	return output
}