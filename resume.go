package wireauth

import (
	"crypto/hmac"
	"crypto/sha256"
)

func VerifyResumeProof(masterKey, sessionSalt, authKeyIDBytes, serverNonce, proofB []byte) bool {
	macA := hmac.New(sha256.New, masterKey)
	macA.Write(sessionSalt)
	proofA := macA.Sum(nil)

	macB := hmac.New(sha256.New, proofA)
	macB.Write(authKeyIDBytes)
	macB.Write(serverNonce)
	expectedProofB := macB.Sum(nil)

	return hmac.Equal(expectedProofB, proofB)
}
