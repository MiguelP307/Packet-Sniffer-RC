package parser

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

func Parse(packet gopacket.Packet){

	//Gets the full packet as raw bytes
	data := packet.Data()

	//Here we get the bytes one the index 12 to 13 where the EthType(2B size) is
	ethType := binary.BigEndian.Uint16(data[12:14])

	switch ethType {
		case 0x0800:
			fmt.Println("IPv4")

		case 0x0806:
			fmt.Println("ARP")

		case 0x86DD:
			fmt.Println("IPv6")

		default:
			fmt.Println("Unknown")
	}

}