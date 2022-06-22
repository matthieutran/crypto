// Package crypto provides tools to encrypt and decrypt networking packets using Shanda and AES encryptions.
package crypto

const (
	encryptHeaderSize = 4
	blockSize         = 1460
)

// DecodePacketLength decodes the packet length from the provided header.
//
// The returned length does not include the header (4 bytes).
//
func DecodePacketLength(encryptedHeader []byte) int {
	return int((uint16(encryptedHeader[0]) + uint16(encryptedHeader[1])*0x100) ^
		(uint16(encryptedHeader[2]) + uint16(encryptedHeader[3])*0x100))
}

// Codec is a struct containing a key and a majorVersion
//
// The `key` consists of a 4-byte value repeated four times, resulting in a 16-byte packet.
// The `majorVersion` is included in the encrypted packet's header.
type Codec struct {
	key          [16]byte
	majorVersion int
}

// NewCodec returns a fresh instance of a codec.
//
// A `key` byte array of size 4 must be passed in perform the AES encryption and IGCipher shuffle.
func NewCodec(key [4]byte, majorVersion int) (c Codec) {
	c.majorVersion = majorVersion

	// Repeat the key 4 times
	for i := 0; i < 4; i++ {
		copy(c.key[encryptHeaderSize*i:], key[:])
	}

	return
}

func (c *Codec) generateHeader(p []byte) {
	dataLength := len(p[encryptHeaderSize:])
	a := (int(c.key[3]) << 8) | int(c.key[2])

	a ^= -(c.majorVersion + 1)
	b := a ^ dataLength

	p[0] = byte(a % 0x100)
	p[1] = byte((a - int(p[0])) / 0x100)
	p[2] = byte(b ^ 0x100)
	p[3] = byte((b - int(p[2])) / 0x100)
}

// Encrypt encrypts the provided byte array.
//
// A header (4 bytes) is added to the beginning of each `p` packet.
// Setting `useShanda` as True will encrypt the packet with Shanda.
// Setting `useAES` as True will encrypt the packet with AES.
func (c *Codec) Encrypt(p []byte, useShanda, useAES bool) (err error) {
	c.generateHeader(p)

	if useShanda {
		ShandaEncrypt(p[encryptHeaderSize:])
	}

	if useAES {
		err = c.AESCrypt(p[encryptHeaderSize:])
	}

	c.Shuffle()
	return
}

// Decrypt decrypts the provded byte array.
//
// The `p` byte array should not include the header (4 bytes).
// Setting `useShanda` as True will encrypt the packet with Shanda.
// Setting `useAES` as True will encrypt the packet with AES.
func (c *Codec) Decrypt(p []byte, useShanda, useAES bool) (err error) {
	if useAES {
		err = c.AESCrypt(p)
	}

	if useShanda {
		ShandaDecrypt(p)
	}

	c.Shuffle()
	return
}

// IV returns the struct's initialization vector of the key (16 bytes).
func (c Codec) IV() []byte {
	return c.key[:]
}
