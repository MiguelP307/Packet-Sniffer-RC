package flow

import "time"

type FlowKey string

type TCPFlow struct {
	Key FlowKey

	SrcIP string
	DstIP string

	SrcPort string
	DstPort string

	StartTime time.Time
	LastSeen  time.Time

	State string // SYN_SENT, ESTABLISHED, FIN_WAIT, CLOSED

	Packets int
	Bytes   int

	// RTT tracking
	LastSeq uint32
	LastAck uint32
	LastSeqTime time.Time
	RTT time.Duration
}

// Generate a key for a specific connection
func makeFlowKey(srcIP, dstIP, srcPort, dstPort string) FlowKey {

	a := srcIP + ":" + srcPort
	b := dstIP + ":" + dstPort

	if a < b {
		return FlowKey(a + "-" + b)
	}
	return FlowKey(b + "-" + a)
}