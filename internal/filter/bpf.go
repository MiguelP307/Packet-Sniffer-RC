package filter

import (
	"github.com/google/gopacket/pcap"
)

type BPF struct {
	Expression string
}

func (b *BPF) Apply(handle *pcap.Handle) error {
	if b.Expression == "" {
		return nil
	}
	return handle.SetBPFFilter(b.Expression)
}

func ApplyBPF(handle *pcap.Handle, expression string) error {
	if expression == "" {
		return nil
	}
	return handle.SetBPFFilter(expression)
}

func TCP() string {
	return "tcp"
}

func UDP() string {
	return "udp"
}

func IPv4() string {
	return "ip"
}
