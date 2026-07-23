package wireauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func LoadPrivateKeyRSA(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wireauth: failed to read %s: %w", path, err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("wireauth: failed to decode PEM in %s", path)
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return priv, nil
	}

	keyAny, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err8 != nil {
		return nil, fmt.Errorf("wireauth: failed to parse RSA private key (neither PKCS#1 nor PKCS#8): %v / %v", err, err8)
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("wireauth: PKCS#8 key in %s is not an RSA private key", path)
	}
	return rsaKey, nil
}
