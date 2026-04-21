package main

import (
	"sniffer/internal/parser"
	"sniffer/internal/capture"
)

func main() {
    
    Interface := "enp0s3"

    packets, _ := capture.Start_Capture(Interface)

    for packet := range packets{
        parser.Parse(packet, Interface)
    }

}