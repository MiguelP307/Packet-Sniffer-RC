package main

import (
	"fmt"
	"sniffer/internal/capture"
	"sniffer/internal/parser"
	"sniffer/internal/view"
)

func main() {
    
    Interface := "enp0s3"

    packets, _ := capture.Start_Capture(Interface)

    for packet := range packets{
        packet := parser.Parse(packet, Interface)

        lines := view.RenderPacket(packet)

        for _, line := range lines {
            fmt.Println(line)
        }
    }


}