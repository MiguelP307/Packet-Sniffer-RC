package layer2

import "encoding/binary"

func HandleEthernet(data []byte) (uint16, []byte) {
	
	//Here we get the bytes one the index 12 to 13 where the EthType(2B size) is
	ethType := binary.BigEndian.Uint16(data[12:14])

	return ethType, data[14:]
}
