package view

import (
	"fmt"
)

func FormatWithMap8(value uint8, m map[uint8]string) string {

	if str, ok := m[value]; ok {
		return fmt.Sprintf("%s (%d / 0x%02x)", str, value, value)
	}

	return fmt.Sprintf("Unknown (%d / 0x%02x)", value, value)
}

func FormatWithMap16(value uint16, m map[uint16]string) string {
	if str, ok := m[value]; ok {
		return fmt.Sprintf("%s (%d / 0x%04x)", str, value, value)
	}

	return fmt.Sprintf("Unknown (%d / 0x%04x)", value, value)
}

func FormatMAC(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5])
}

func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func Fit(s string, width int) string {
	if len(s) > width {
		return s[:width-1] + "…"
	}
	return fmt.Sprintf("%-*s", width, s)
}