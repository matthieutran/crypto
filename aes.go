package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

var userKey = [...]byte{
	0x13, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x00, 0x00,
	0xb4, 0x00, 0x00, 0x00,
	0x1b, 0x00, 0x00, 0x00,
	0x0f, 0x00, 0x00, 0x00,
	0x33, 0x00, 0x00, 0x00,
	0x52, 0x00, 0x00, 0x00,
}

func AESCrypt(key []byte, buf []byte) (err error) {
	var pos, tPos, cbWrite, cb int32 = 0, 0, 0, int32(len(buf))
	var first byte = 1

	cb = int32(len(buf))
	for cb > pos {
		tPos = blockSize - int32(first*4)
		if cb > pos+tPos {
			cbWrite = tPos
		} else {
			cbWrite = cb - pos
		}

		block, err := aes.NewCipher(userKey[:])
		if err != nil {
			err = errors.New("error encrypting with AES")
			return err
		}

		stream := cipher.NewOFB(block, key[:])
		stream.XORKeyStream(buf[pos:pos+cbWrite], buf[pos:pos+cbWrite])
		pos += tPos

		if first == 1 {
			first = 0
		}
	}

	return
}
