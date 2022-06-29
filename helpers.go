package crypto

func encodeVersion(version uint16) (res uint16) {
	res = 0xFFFF - version
	res = (res >> 8 & 0xFF) | (res << 8 & 0xFF00)
	return
}

// DecodePacketLength decodes the packet length from the provided header.
//
// The returned length does not include the header (4 bytes).
//
func DecodePacketLength(encryptedHeader []byte) int {
	return int((uint16(encryptedHeader[0]) + uint16(encryptedHeader[1])*0x100) ^
		(uint16(encryptedHeader[2]) + uint16(encryptedHeader[3])*0x100))
}
