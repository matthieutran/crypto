// Package crypto provides tools to encrypt and decrypt networking packets using Shanda and AES encryptions.
package crypto

const (
	encryptedHeaderSize = 4
	blockSize           = 1460
)

// Codec is a struct containing a key and a majorVersion
//
// The `key` consists of a 4-byte value repeated four times, resulting in a 16-byte packet.
// The `majorVersion` is included in the encrypted packet's header.
type Codec struct {
	ivRecv       [16]byte
	ivSend       [16]byte
	majorVersion uint16
}

// NewCodec returns a fresh instance of a codec.
func NewCodec(ivRecv, ivSend [4]byte, majorVersion int) (c Codec) {
	c.majorVersion = encodeVersion(uint16(majorVersion))

	// Repeat the key 4 times
	for i := 0; i < 4; i++ {
		copy(c.ivRecv[encryptedHeaderSize*i:], ivRecv[:])
		copy(c.ivSend[encryptedHeaderSize*i:], ivSend[:])
	}

	return
}

func (c *Codec) generateHeader(buffer []byte) {
	cb := uint16(len(buffer) - encryptedHeaderSize)

	iiv := uint16(c.ivSend[3] & 0xFF)
	iiv |= uint16(c.ivSend[2]) << 8 & 0xFF00

	iiv ^= c.majorVersion
	mlength := uint16((cb << 8 & 0xFF00) | cb>>8)
	xoredIv := iiv ^ mlength

	buffer[0] = byte(iiv >> 8 & 0xFF)
	buffer[1] = byte(iiv & 0xFF)
	buffer[2] = byte(xoredIv >> 8 & 0xFF)
	buffer[3] = byte(xoredIv & 0xFF)
}

// Encrypt encrypts the provided byte array.
//
// A header (4 bytes) is added to the beginning of each `p` packet.
// Setting `useShanda` as True will encrypt the packet with Shanda.
// Setting `useAES` as True will encrypt the packet with AES.
func (c *Codec) Encrypt(buf []byte, useShanda, useAES bool) (res []byte, err error) {
	res = []byte{0, 0, 0, 0}
	res = append(res, buf...)
	c.generateHeader(res)

	if useShanda {
		ShandaEncrypt(res[encryptedHeaderSize:])
	}
	if useAES {
		err = AESCrypt(res[encryptedHeaderSize:])
	}

	// Shuffle IV keys
	c.Shuffle(true)

	return
}

// Decrypt decrypts the provded byte array.
//
// The `p` byte array should not include the header (4 bytes).
// Setting `useShanda` as True will encrypt the packet with Shanda.
// Setting `useAES` as True will encrypt the packet with AES.
func (c *Codec) Decrypt(buf []byte, useShanda, useAES bool) (err error) {
	if useAES {
		err = AESCrypt(buf)
	}

	if useShanda {
		ShandaDecrypt(buf)
	}

	c.Shuffle(false)
	return
}

// IV returns the struct's initialization vector of the key (16 bytes).
func (c Codec) IV() []byte {
	return c.ivSend[:]
}
