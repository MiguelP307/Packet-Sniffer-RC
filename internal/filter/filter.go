package filter

import "sniffer/internal/model"

type Filter struct {
	Protocol string
	SrcIP    string
	DstIP    string

	Or []*Filter
}

func (f *Filter) Match(p model.ParsedPacket) bool {

	if len(f.Or) > 0 {
		for _, sub := range f.Or {
			if sub.Match(p) {
				return true
			}
		}
		return false
	}

	if f.Protocol != "" && p.Protocol != f.Protocol {
		return false
	}

	if f.SrcIP != "" && p.SrcIP != f.SrcIP {
		return false
	}

	if f.DstIP != "" && p.DstIP != f.DstIP {
		return false
	}

	return true
}
