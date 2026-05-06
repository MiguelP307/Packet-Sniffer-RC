package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sniffer/internal/model"
	"time"
)

type Logger struct {
	file *os.File
}

func NewLogger(iface string) (*Logger, error) {

	err := os.MkdirAll("logs", 0755)
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")

	filename := fmt.Sprintf("%s_%s.log", iface, timestamp)

	fullPath := filepath.Join("logs", filename)

	file, err := os.OpenFile(
		fullPath,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)

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

	output += "=============== Packet ===============\n"
	output += fmt.Sprintf("Time: %s\n", packet.Timestamp)
	output += fmt.Sprintf("Iface: %s\n", packet.Interface)
	output += fmt.Sprintf("Length: %d\n", packet.Length)

	output += "\n"

	protocol := getProtocol(packet)
	output += fmt.Sprintf("Protocol: %s\n", protocol)

	for _, layer := range packet.Layers {

		output += fmt.Sprintf("[%s]\n", layer.LayerType())

		for _, line := range layer.View() {
			output += line + "\n"
		}

		output += "\n\n"
	}

	output += fmt.Sprintf("Info: %s\n", packet.Infos)
	output += "=======================================\n\n\n\n\n"

	return output
}

func getProtocol(p model.ParsedPacket) string {
	if len(p.Layers) == 0 {
		return "Unknown"
	}

	return p.Layers[len(p.Layers)-1].ProtocolType()
}
