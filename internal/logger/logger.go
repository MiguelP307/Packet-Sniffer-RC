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

	var file *os.File
	var err error

	if filename != "" {
		file, err = os.Create(filename)
		if err != nil {
			return nil, err
		}
	}

	return &Logger{file: file}, nil
}

func (l *Logger) Log(packet model.ParsedPacket) {

	output := packet.String()

	fmt.Println(output)

	if l.file != nil {
		l.file.WriteString(output + "\n")
	}
}

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}
