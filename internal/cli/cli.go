package main

import (
	"fmt"
	"os"
	"time"

	"sniffer/internal/capture"
	"sniffer/internal/model"
	"sniffer/internal/parser"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
)

var (
	liveStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("46")). // green
		Bold(true)

	pausedStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("196")). // red
		Bold(true)
)

/* -------------------- STATE -------------------- */

type state int

const (
	mainMenu state = iota
	startMenu
	loadMenu
	selectInterface
	selectFilter
	packetViewer
	packetDetail
)

/* -------------------- LIST ITEM -------------------- */

type item string

func (i item) Title() string       { return string(i) }
func (i item) Description() string { return "" }
func (i item) FilterValue() string { return string(i) }

/* -------------------- MODEL -------------------- */

type modelCLI struct {
	state state

	mainList list.Model
	loadList list.Model
	startList list.Model

	interfaces []string
	filters    []string

	selectedInterface string
	selectedFilter    string

	packets        []model.ParsedPacket
	selectedPacket model.ParsedPacket

	cursor         int
	autoScroll bool
	paused bool

	captureChan <-chan gopacket.Packet

	layerIndex int
}

type packetMsg model.ParsedPacket

/* -------------------- INIT -------------------- */

func initialModel() modelCLI {
	items := []list.Item{
		item("Start Capture"),
		item("Load Capture"),
		item("Exit"),
	}

	l := list.New(items, list.NewDefaultDelegate(), 30, 17)
	l.Title = "PL94 - Packet Sniffer"

	return modelCLI{
		state:     mainMenu,
		mainList:  l,
		packets:   []model.ParsedPacket{},
	}
}

/* -------------------- BUBBLE TEA INIT -------------------- */

func (m modelCLI) Init() tea.Cmd {
	return nil
}

/* -------------------- UPDATE -------------------- */

func (m modelCLI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {

	// -------------- GLOBAL MESSAGES -------------
	switch msg := msg.(type) {

	case packetMsg:

		if !m.paused {
			m.packets = append(m.packets, model.ParsedPacket(msg))
		}

		if m.autoScroll {
			m.cursor = len(m.packets) - 1
		}

		return m, waitForPacket(m.captureChan, "enp0s3")

	}
	// ------------ State Machine -----------------
	switch m.state {

	/* ---------------- MAIN MENU ---------------- */
	case mainMenu:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {

			case "enter":
				switch m.mainList.SelectedItem().(item) {

				case "Start Capture":
					m.state = startMenu
					m.startList = buildStartList()

				case "Load Capture":
					m.state = loadMenu
					m.loadList = buildLoadList()

				case "Exit":
					return m, tea.Quit
				}

			case "q", "ctrl+c":
				return m, tea.Quit
			}
		}

		var cmd tea.Cmd
		m.mainList, cmd = m.mainList.Update(msg)
		return m, cmd

	/* ---------------- LOAD MENU ---------------- */
	case loadMenu:
		switch msg := msg.(type) {

		case tea.KeyMsg:
			switch msg.String() {
			case "enter":
				selected := m.loadList.SelectedItem().(item)

				m.packets = loadPacketsFromFile(string(selected))
				m.state = packetViewer
			}
		}

		var cmd tea.Cmd
		m.loadList, cmd = m.loadList.Update(msg)
		return m, cmd

	/* ---------------- PACKET VIEWER ---------------- */
	case packetViewer:
		switch msg := msg.(type) {

		case tea.KeyMsg:
			switch msg.String() {

			case "up":
				if m.cursor > 0 {
					m.cursor--
					m.autoScroll = false
				}

			case "down":
				if m.cursor < len(m.packets)-1 {
					m.cursor++
					if m.cursor == len(m.packets)-1 {
						m.autoScroll = true
					}
				}

			case "enter":
				m.selectedPacket = m.packets[m.cursor]
				m.state = packetDetail

			case "p":
				m.paused = !m.paused

			case "esc":
				m.captureChan = nil
				m.state = mainMenu
			}
		}
		return m, nil

	/* ---------------- PACKET DETAIL ---------------- */
	case packetDetail:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {

			case "esc":
				m.state = packetViewer

			case "left":
				if m.layerIndex > 0 {
					m.layerIndex--
				}

			case "right":
				if m.layerIndex < len(m.selectedPacket.Layers)-1 {
					m.layerIndex++
				}
			}
		}
		return m, nil

	/* ---------------- START MENU ---------------- */
	case startMenu:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {

			case "enter":
				switch m.startList.SelectedItem().(item) {

				case "Interface":
					m.state = selectInterface

				case "Filter":
					m.state = selectFilter
				
				case "Capture":
					// Start Capture Here
					m.state = packetViewer

					ch, _ := capture.Start_Capture("enp0s3")

					m.paused = false

					m.captureChan = ch
					m.state = packetViewer

					return m, waitForPacket(m.captureChan, "enp0s3")
				}

			case "esc", "b":
				m.state = mainMenu
			}
		}

		var cmd tea.Cmd
		m.startList, cmd = m.startList.Update(msg)
		return m, cmd
	
	case selectInterface:
		// Selecionar interface e adicionar a frente do menu anterior

	case selectFilter:	
		// Selecionar filtro e mostrar no menu anterior
	
	}

	return m, nil
}

/* -------------------- VIEW -------------------- */

func (m modelCLI) View() string {

	switch m.state {

	case mainMenu:
		return m.mainList.View()

	case startMenu:
		return m.startList.View()

	case loadMenu:
		return m.loadList.View()

	case packetViewer:
		return renderPacketList(m)

	case packetDetail:
		return renderPacketDetail(m.selectedPacket, m.layerIndex)
	}

	return ""
}

/* -------------------- HELPERS -------------------- */

func buildLoadList() list.Model {
	files := []list.Item{
		item("logs/capture1.txt"),
		item("logs/capture2.txt"),
		item("logs/capture3.txt"),
	}

	l := list.New(files, list.NewDefaultDelegate(), 40, 40)
	l.Title = "Load Capture File"
	return l
}

func buildStartList() list.Model {
	options := []list.Item{
		item("Interface:"),
		item("Filter: "),
		item("Capture"),
	}

	l := list.New(options, list.NewDefaultDelegate(), 40, 17)
	l.Title = "Capture Menu"
	return l
}

func loadPacketsFromFile(file string) []model.ParsedPacket {
	// fake data (substitui por parsing real depois)
	return []model.ParsedPacket{
	}
}

func renderPacketList(m modelCLI) string {
	title := "PACKETS"

	if !m.paused {
		title = liveStyle.Render("PACKETS (LIVE)")
	} else {
		title = pausedStyle.Render("PACKETS (PAUSED)")
	}

	out := title + "\n\n"

	for i, p := range m.packets {
		cursor := " "
		if i == m.cursor {
			cursor = ">"
		}

		// last layer = highest protocol
		proto := p.Layers[len(p.Layers)-1].ProtocolType()

		protoStyled := lipgloss.NewStyle().
			Foreground(lipgloss.Color("39")). // blue
			Render(proto)

		out += fmt.Sprintf("%s %3d  %-8s  %-40s  %5d bytes\n",
			cursor,
			i+1,
			protoStyled,
			p.Infos,
			p.Length,
		)
	}

	out += "\nENTER = details | ESC = back | S = save | P = pause"

	return out
}

func renderPacketDetail(p model.ParsedPacket, layerIndex int) string {

	out := ""

	// summary always visible
	out += fmt.Sprintf("Timestamp: %s\n", p.Timestamp)
	out += fmt.Sprintf("Interface: %s\n", p.Interface)
	out += fmt.Sprintf("Length: %d\n\n", p.Length)

	layer := p.Layers[layerIndex]

	out += fmt.Sprintf("%s: %s\n",
		layer.LayerType(),
		layer.ProtocolType(),
	)

	for _, line := range layer.View() {
		out += "  " + line + "\n"
	}

	out += fmt.Sprintf("\nLayer %d/%d", layerIndex+1, len(p.Layers))
	out += "\n←/→ switch layer | ESC back"

	return out
}


func waitForPacket(ch <-chan gopacket.Packet, iface string) tea.Cmd {
	return func() tea.Msg {
		pkt, ok := <-ch
		if !ok {
			return nil
		}

		parsed := parser.Parse(pkt, iface)
		return packetMsg(parsed)
	}
}

/* -------------------- MAIN -------------------- */

func main() {
	p := tea.NewProgram(initialModel(),	tea.WithAltScreen())

	if err := p.Start(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	
	_ = time.Now()
}