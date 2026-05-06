package cli

import (
	"fmt"
	"strings"
	"time"

	"sniffer/internal/capture"
	"sniffer/internal/model"
	"sniffer/internal/parser"
	"sniffer/internal/view"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
)

// --------------- FAKE DATA -------------

func getFakeFilters() []string {
	return []string{
		"",
		"tcp port 80",
		"udp",
		"icmp",
		"host 8.8.8.8",
		"port 443",
	}
}


// --------------- STYLE ------------------

var (
	liveStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("46")).
		Bold(true)

	pausedStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("196")).
		Bold(true)
)

/* ---------- RenderPacketView Table ------------ */

const (
	colID       = 4
	colTime     = 10
	colProto    = 10
	colInfo     = 40
	colLength   = 8
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

type menuItem struct {
	label string
	value string
}

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
	ifaceList list.Model
	filterList list.Model

	interfaces []string
	filters    []string

	selectedInterface string
	selectedFilter    string

	packets        []model.ParsedPacket
	selectedPacket model.ParsedPacket

	cursor int

	offset int
	height int

	autoScroll bool
	paused bool

	captureChan <-chan gopacket.Packet

	layerIndex int
}

type packetMsg model.ParsedPacket

/* -------------------- INIT -------------------- */

func InitialModel() modelCLI {
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

			if m.height > 0 {
				m.offset = len(m.packets) - m.height
				if m.offset < 0 {
					m.offset = 0
				}
			}
		}

		return m, waitForPacket(m.captureChan, m.selectedInterface)

	case tea.WindowSizeMsg:
		m.height = msg.Height - 6
		return m, nil

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

					if m.cursor < m.offset {
						m.offset--
					}
				}

			case "down":
				if m.cursor < len(m.packets)-1 {
					m.cursor++

					if m.cursor >= m.offset+m.height {
						m.offset++
					}

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
				m.packets = []model.ParsedPacket{}
				m.selectedInterface = ""
				m.selectedFilter = ""
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

				case "Interface:":
					ifaces, err := capture.ListInterfaces()
					if err != nil {
						return m, nil
					}

					m.interfaces = ifaces
					m.ifaceList = buildInterfaceList(ifaces)
					m.state = selectInterface

				case "Filter:":
					filters := getFakeFilters()

					m.filters = filters
					m.filterList = buildFilterList(filters)
					m.state = selectFilter
				
				case "Capture":

					ch, _ := capture.Start_Capture(m.selectedInterface, m.selectedFilter)

					m.paused = false

					m.captureChan = ch
					m.state = packetViewer

					return m, waitForPacket(m.captureChan, m.selectedInterface)
				}

			case "esc", "b":
				m.state = mainMenu
			}
		}

		var cmd tea.Cmd
		m.startList, cmd = m.startList.Update(msg)
		return m, cmd
	
	case selectInterface:
		var cmd tea.Cmd

		m.ifaceList, cmd = m.ifaceList.Update(msg)

		switch msg := msg.(type) {

		case tea.KeyMsg:
			switch msg.String() {

			case "enter":
				selected := m.ifaceList.SelectedItem().(item)

				m.selectedInterface = string(selected)
				m.state = startMenu

				return m, tea.Batch(
					tea.ClearScreen,
				)

			case "esc":
				m.state = startMenu
			}
		}

		return m, cmd

	case selectFilter:	
		var cmd tea.Cmd

		m.filterList, cmd = m.filterList.Update(msg)

		switch msg := msg.(type) {

		case tea.KeyMsg:
			switch msg.String() {

			case "enter":
				selected := m.filterList.SelectedItem().(item)

				m.selectedFilter = string(selected)
				m.state = startMenu

				return m, tea.Batch(
					tea.ClearScreen,
				)


			case "esc":
				m.state = startMenu
			}
		}

		return m, cmd
	
	}

	return m, nil
}

/* -------------------- VIEW -------------------- */

func (m modelCLI) View() string {

	switch m.state {

	case mainMenu:
		return m.mainList.View()

	case startMenu:
		items := m.startList.Items()

		for i := range items {
			it := items[i].(item)

			switch string(it) {
			case "Interface:":
				if m.selectedInterface != "" {
					items[i] = item(fmt.Sprintf("Interface: %s", m.selectedInterface))
				}

			case "Filter:":
				if m.selectedFilter != "" {
					items[i] = item(fmt.Sprintf("Filter: %s", m.selectedFilter))
				}
			}
		}

		temp := m.startList
		temp.SetItems(items)

		return temp.View()

	case selectInterface:
		if len(m.ifaceList.Items()) == 0 {
			return "Loading interfaces..."
		}
		return m.ifaceList.View()

	case selectFilter:
		if len(m.filterList.Items()) == 0 {
			return "Loading filters..."
		}
		return m.filterList.View()

	case loadMenu:
		return m.loadList.View()

	case packetViewer:
		return renderPacketList(m)

	case packetDetail:
		return renderPacketDetail(m.selectedPacket, m.layerIndex)
	}

	return ""
}

func (m modelCLI) startMenuLabels() map[string]string {
	return map[string]string{
		"Interface:": m.selectedInterface,
		"Filter:":    m.selectedFilter,
	}
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
		item("Filter:"),
		item("Capture"),
	}

	l := list.New(options, list.NewDefaultDelegate(), 40, 17)
	l.Title = "Capture Menu"
	return l
}

func buildInterfaceList(ifaces []string) list.Model {
	items := make([]list.Item, len(ifaces))

	for i, iface := range ifaces {
		items[i] = item(iface)
	}

	l := list.New(items, list.NewDefaultDelegate(), 50, 20)
	l.Title = "Select Interface"
	return l
}

func buildFilterList(filters []string) list.Model {
	items := make([]list.Item, len(filters))

	for i, filter := range filters {
		items[i] = item(filter)
	}

	l := list.New(items, list.NewDefaultDelegate(), 50, 20)
	l.Title = "Select BPF Filter"
	return l
}

func buildStartListWithState(iface, filter string) list.Model {

	interfaceLabel := "Interface:"
	if iface != "" {
		interfaceLabel = "Interface: " + iface
	}

	filterLabel := "Filter:"
	if filter != "" {
		filterLabel = "Filter: " + filter
	}

	options := []list.Item{
		item(interfaceLabel),
		item(filterLabel),
		item("Capture"),
	}

	l := list.New(options, list.NewDefaultDelegate(), 40, 17)
	l.Title = "Capture Menu"

	return l
}

func loadPacketsFromFile(file string) []model.ParsedPacket {
	// fake data 
	return []model.ParsedPacket{
	}
}

func renderPacketList(m modelCLI) string {

	// ---------- TITLE ----------
	title := "PACKETS"

	if !m.paused {
		title = liveStyle.Render("PACKETS (LIVE)")
	} else {
		title = pausedStyle.Render("PACKETS (PAUSED)")
	}

	out := title + "\n"

	// ---------- TOP LABLE ----------
	header := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s",
		2, "", 
		colID, "ID",
		colTime, "TIME",
		colProto, "PROTOCOL",
		colInfo, "INFO",
		colLength, "LENGTH",
	)

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("240"))

	out += headerStyle.Render(header) + "\n"
	out += strings.Repeat("-", colID+colTime+colProto+colInfo+colLength+5) + "\n"

	end := m.offset + m.height
	if end > len(m.packets) {
		end = len(m.packets)
	}

	var firstTime time.Time
	hasPackets := len(m.packets) > 0

	if hasPackets {
		firstTime = m.packets[0].Timestamp
	}

	// ---------- ROW BUILDER ----------
	for i := m.offset; i < end; i++ {
    	p := m.packets[i]

		// ---------- CURSOR ----------
		cursor := " "
		if i == m.cursor {
			cursor = "▶"
		}	

		cursor = fmt.Sprintf("%-2s", cursor)

		// ---------- TIME ELAPSE FORMATTING ----------
		elapsed := 0.0
		if hasPackets {
			elapsed = p.Timestamp.Sub(firstTime).Seconds()
			
		}
		timeStr := fmt.Sprintf("%.3fs", elapsed)


		// ---------- PROTOCOL FORMATTING ----------
		proto := "UNKNOWN"
		if len(p.Layers) > 0 {
			proto = p.Layers[len(p.Layers)-1].ProtocolType()
		}

		protoStyled := lipgloss.NewStyle().
			Foreground(lipgloss.Color("39")).
			Render(fmt.Sprintf("%-*s", colProto, proto))

		
		// ---------- INFOS EXTRA FORMATTING ----------
		info := view.Truncate(p.Infos, colInfo)

		// ---------- ROW PRINT ----------
		out += fmt.Sprintf("%s %-*d %-*s %-*s %-*s %-*d\n",
			cursor,
			colID, i+1,
			colTime, timeStr,
			colProto, protoStyled,
			colInfo, info,
			colLength, p.Length,
		)
	}

	// ---------- PAGING ----------
	if len(m.packets) == 0 {
		out += "\nShowing 0 packets"
	} else {
		out += fmt.Sprintf("\nShowing %d-%d of %d",
			m.offset+1,
			end,
			len(m.packets),
		)
	}

	// ---------- FOOTER ----------
	out += "\nENTER = details | ESC = back | S = save | P = pause"

	return out
}

func renderPacketDetail(p model.ParsedPacket, layerIndex int) string {

	out := ""

	out += fmt.Sprintf("Timestamp: %s\n", p.Timestamp.Format("15:04:05.000"))
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

	style := lipgloss.NewStyle().
		PaddingTop(1).
		PaddingLeft(2).
		PaddingRight(2)

	return style.Render(out)
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

func interfaceLabel(selected string) string {
	if selected == "" {
		return "Interface:"
	}
	return fmt.Sprintf("Interface: %s", selected)
}

/* -------------------- RUN -------------------- */

func Run() error {
	p := tea.NewProgram(InitialModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}