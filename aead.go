package wireauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
)

func EncryptAESGCM(key, plaintext []byte, seq uint64) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seq)

	ciphertext := gcm.Seal(nil, nonce, plaintext, seqBytes)

	packet := make([]byte, len(seqBytes)+len(nonce)+len(ciphertext))
	copy(packet[0:8], seqBytes)
	copy(packet[8:8+len(nonce)], nonce)
	copy(packet[8+len(nonce):], ciphertext)
	return packet, nil
}

func DecryptAESGCM(key, packet []byte) (plaintext []byte, seq uint64, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}
	if len(packet) < 8+gcm.NonceSize() {
		return nil, 0, ErrPacketTooShort
	}

	seqBytes := packet[0:8]
	nonce := packet[8 : 8+gcm.NonceSize()]
	ciphertext := packet[8+gcm.NonceSize():]

	seq = binary.BigEndian.Uint64(seqBytes)

	plaintext, err = gcm.Open(nil, nonce, ciphertext, seqBytes)
	if err != nil {
		return nil, 0, ErrDecryptionFailed
	}
	return plaintext, seq, nil
}
