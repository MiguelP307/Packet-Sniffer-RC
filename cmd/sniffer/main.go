package main

import (
	"sniffer/internal/parser"
	"sniffer/internal/capture"
)

func main() {
    
    packets, _ := capture.Start_Capture("enp0s3")

    for packet := range packets{
        parser.Parse(packet)
    }

}