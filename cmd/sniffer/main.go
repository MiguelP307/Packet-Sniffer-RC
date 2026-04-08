package main

import (
    "fmt"
    "log"

    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

func main() {
    handle, err := pcap.OpenLive("enp0s3", 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    for packet := range packetSource.Packets() {
        fmt.Println(packet)
    }
}