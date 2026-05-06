package logger

import (
	"fmt"
	"os"
	"sniffer/internal/model"
)

type Logger struct {
	file *os.File
}

func NewLogger(filename string) (*Logger, error) {

	file, err := os.OpenFile("sniffer.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &Logger{file: file}, nil
}

func (l *Logger) Log(packet model.ParsedPacket) {
	if l.file != nil {
		l.file.WriteString(formatPacket(packet))
	}
}

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}
func formatPacket(packet model.ParsedPacket) string {

	output := ""

	output += "--- Packet ---\n"
	output += fmt.Sprintf("Time: %s\n", packet.Timestamp)
	output += fmt.Sprintf("Interface: %s\n", packet.Interface)
	output += fmt.Sprintf("Length: %s\n", packet.Length)

	protocol := getProtocol(packet)
	output += fmt.Sprintf("Protocol: %s\n", protocol)

	for _, layer := range packet.Layers {
		output += fmt.Sprintf("[%s]\n", layer.LayerType())

		for _, line := range layer.View() {
			output += line + "\n"
		}
	}

	output += fmt.Sprintf("Info: %s\n", packet.Infos)
	output += "--------------\n"

	return output
}

func getProtocol(p model.ParsedPacket) string {
	if len(p.Layers) == 0 {
		return "Unknown"
	}
	return p.Layers[len(p.Layers)-1].ProtocolType()
}
