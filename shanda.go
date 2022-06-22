package crypto

func ror(val byte, num int) byte {
	for i := 0; i < num; i++ {
		var lowBit int
		if val&1 > 0 {
			lowBit = 1
		} else {
			lowBit = 0
		}

		val >>= 1
		val |= byte(lowBit << 7)
	}

	return val
}

func rol(val byte, num int) byte {
	var highBit int

	for i := 0; i < num; i++ {
		if val&0x80 > 0 {
			highBit = 1
		} else {
			highBit = 0
		}

		val <<= 1
		val |= byte(highBit)
	}

	return val
}

func ShandaEncrypt(buf []byte) {
	var j int32
	var a, c byte

	for i := byte(0); i < 3; i++ {
		a = 0
		for j = int32(len(buf)); j > 0; j-- {
			c = buf[int32(len(buf))-j]
			c = rol(c, 3)
			c = byte(int32(c) + j)
			c ^= a
			a = c
			c = ror(a, int(j))
			c ^= 0xFF
			c += 0x48
			buf[int32(len(buf))-j] = c
		}

		a = 0
		for j = int32(len(buf)); j > 0; j-- {
			c = buf[j-1]
			c = rol(c, 4)
			c = byte(int32(c) + j)
			c ^= a
			a = c
			c ^= 0x13
			c = ror(c, 3)
			buf[j-1] = c
		}
	}
}

func ShandaDecrypt(buf []byte) {
	var j int32
	var a, b, c byte

	for i := byte(0); i < 3; i++ {
		a = 0
		b = 0
		for j = int32(len(buf)); j > 0; j-- {
			c = buf[j-1]
			c = rol(c, 3)
			c ^= 0x13
			a = c
			c ^= b
			c = byte(int32(c) - j)
			c = ror(c, 4)
			b = a
			buf[j-1] = c
		}

		a = 0
		b = 0
		for j = int32(len(buf)); j > 0; j-- {
			c = buf[int32(len(buf))-j]
			c -= 0x48
			c ^= 0xFF
			c = rol(c, int(j))
			a = c
			c ^= b
			c = byte(int32(c) - j)
			c = ror(c, 3)
			b = a
			buf[int32(len(buf))-j] = c
		}
	}
}
