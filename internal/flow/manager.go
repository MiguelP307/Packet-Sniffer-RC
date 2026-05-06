package flow

import (
	"sniffer/internal/model"
)

type Manager struct {
	Flows map[FlowKey]*TCPFlow
}

func NewManager() *Manager {
	return &Manager{
		Flows: make(map[FlowKey]*TCPFlow),
	}
}

func (m *Manager) Process(p model.ParsedPacket) {

	data := ExtractFlowData(p)

	if data.Protocol != "TCP" {
		return
	}

	key := makeFlowKey(
		data.SrcIP,
		data.DstIP,
		data.SrcPort,
		data.DstPort,
	)

	flow, exists := m.Flows[key]
	if !exists {
		flow = &TCPFlow{
			Key:       key,
			SrcIP:     data.SrcIP,
			DstIP:     data.DstIP,
			SrcPort:   data.SrcPort,
			DstPort:   data.DstPort,
			StartTime: p.Timestamp,
			State:     "NEW",
		}
		m.Flows[key] = flow
	}

	// --------- Basic Stats

	flow.Packets++
	flow.Bytes += p.Length
	flow.LastSeen = p.Timestamp

	tcp := data.TCP
	if tcp == nil {
		return
	}

	// -------- Connection States 

	switch flow.State {

	case "NEW":
		if tcp.SynFlag {
			flow.State = "SYN_SENT"
		}

	case "SYN_SENT":
		if tcp.SynFlag && tcp.AckFlag {
			flow.State = "ESTABLISHED"
		}

	case "ESTABLISHED":
		if tcp.FinFlag {
			flow.State = "FIN_WAIT_1"
		}

	case "FIN_WAIT_1":
		if tcp.AckFlag {
			flow.State = "FIN_WAIT_2"
		}

	case "FIN_WAIT_2":
		if tcp.FinFlag {
			flow.State = "TIME_WAIT"
		}

	case "TIME_WAIT":
		flow.State = "CLOSED"
	}

}