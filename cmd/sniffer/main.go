package main

import (
	"fmt"
	"os"
	"sniffer/internal/cli"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	p := tea.NewProgram(cli.InitialModel(),	tea.WithAltScreen())

	if err := p.Start(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	
	_ = time.Now()
}