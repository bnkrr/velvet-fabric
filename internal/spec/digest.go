package spec

import (
	"crypto/hmac"
	"crypto/sha256"
)

func deriveDigest(key []byte, values ...string) [32]byte {
	mac := hmac.New(sha256.New, key)
	for _, value := range values {
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(value))
	}
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}
