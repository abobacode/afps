package cryptos

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/abobacode/afps/logger"
)

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs5UnPadding(origData []byte) []byte {
	return origData[:(len(origData) - int(origData[len(origData)-1]))]
}

// AESCBCEncrypt is given key, iv to encrypt the plainText in AES CBC way.
func AESCBCEncrypt(key, iv, plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	if len(plainText)%aes.BlockSize != 0 {
		plainText = pkcs5Padding(plainText, block.BlockSize())
	}
	ciphertext := make([]byte, len(plainText))
	mode.CryptBlocks(ciphertext, plainText)

	return ciphertext, nil

}

// AESCBCDecrypt is given key, iv to decrypt the cipherText in AES CBC way.
func AESCBCDecrypt(key, iv, cipherText []byte) ([]byte, error) {
	if len(cipherText) == 0 {
		return nil, fmt.Errorf("ciphertext can't be plain")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, cipherText)
	logger.Println("AES-CBC Decrpypt: PlainText Length:", len(plainText))
	if len(cipherText)%aes.BlockSize == 0 {
		return plainText, nil
	}
	return pkcs5UnPadding(plainText), nil
}

// AESECBEncrypt is given key to encrypt the plainText in AES ECB way.
func AESECBEncrypt(key, plainText []byte) ([]byte, error) {
	logger.Println("AES-ECB Encrpypt: PlainText Length:", len(plainText))
	if len(plainText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("need a multiple of the blocksize")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, len(plainText))
	size := aes.BlockSize

	for bs, be := 0, size; bs < len(plainText); bs, be = bs+size, be+size {
		block.Encrypt(cipherText[bs:be], plainText[bs:be])
	}

	return cipherText, nil
}

// AESECBDecrypt is given key to decrypt the cipherText in AES ECB way.
func AESECBDecrypt(key, cipherText []byte) ([]byte, error) {
	logger.Println("AES-ECB: cipherText Length:", len(cipherText))
	if len(cipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("input not full blocks")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(cipherText))
	size := aes.BlockSize

	for bs, be := 0, size; bs < len(plainText); bs, be = bs+size, be+size {
		block.Decrypt(plainText[bs:be], cipherText[bs:be])
	}

	return plainText, nil
}
