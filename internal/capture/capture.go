package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)


func Start_Capture(interfaceName string) (<- chan gopacket.Packet, error){

	handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
	if err != nil{
		panic(err)
	}

	ch := make(chan gopacket.Packet)

	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			ch <- packet
		}
		close(ch)
	}()

	return ch, nil
}

