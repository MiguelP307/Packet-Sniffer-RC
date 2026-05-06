package capture

import (
	"sniffer/internal/filter"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)


func Start_Capture(interfaceName string, filterExpr string) (<- chan gopacket.Packet, error){

	handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
	if err != nil{
		panic(err)
	}

	if err := filter.ApplyBPF(handle, filterExpr); err != nil {
		return nil, err
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

func ListInterfaces() ([]string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var ifaces []string
	for _, d := range devs {
		ifaces = append(ifaces, d.Name)
	}

	return ifaces, nil
}