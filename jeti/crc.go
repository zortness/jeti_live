package jeti

// Crc16Ref calculates the Jeti standard Reflected CRC-16 (poly=0x8408, init=0x0000).
func Crc16Ref(data []byte) uint16 {
	var crc uint16 = 0x0000
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if (crc & 1) != 0 {
				crc = (crc >> 1) ^ 0x8408
			} else {
				crc = crc >> 1
			}
		}
	}
	return crc
}
