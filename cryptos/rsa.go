package cryptos

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func RSAEncryptByKey(publicKey *rsa.PublicKey, origData []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, origData, nil)
}

func RSAEncryptByCert(pemCertificate *rsa.PublicKey, origData []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pemCertificate, origData, nil)
}

func RSADecryptByKey(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
}
