package filter

import "sniffer/internal/model"

type Filter struct{}

func (f *Filter) Match(p model.ParsedPacket) bool {
	return true
}
