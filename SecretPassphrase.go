package main

import (
	"crypto/aes"
	cipherLib "crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"strings"
)

const magicChecksum = "::::MAGIC::::"
func DecryptSecret(passwordStr string,secret []byte)string{
	var clearString []byte
	password,err := base64.StdEncoding.DecodeString(passwordStr)
	if err != nil{
		log.Fatalln(err)
	}
	if password[0] == 1{
		trimCutSet := "\u0001\u0004\u0007\u000e\u000f\u0010\b"
		kk := decryptNewFormatCredentials(password,secret)
		return strings.Trim(kk,trimCutSet)
		//return decryptNewFormatCredentials(password,secret)
	}else{
		clearString = decryptAes128Ecb(password,secret)
	}
	return strings.Split(string(clearString),magicChecksum)[0]
}
func DecryptHudsonSecret(masterKey []byte, hudsonSecret []byte) ([]byte) {
	hashedMasterKey := hashMasterKey(masterKey)
	decryptedSecret := decryptAes128Ecb(hudsonSecret, hashedMasterKey)

	if secretContainsChecksum(decryptedSecret) {
		return decryptedSecret[:16]
	} else {
		return nil
	}
}

func secretContainsChecksum(encryptedSecret []byte) bool {
	return strings.Contains(string(encryptedSecret), magicChecksum)
}

/*
   Hash needs to be 16 bytes as Jenkins uses AES-128 encryption.
*/
func hashMasterKey(masterKey []byte) []byte {
	hasher := sha256.New()
	hasher.Write(masterKey)
	return hasher.Sum(nil)[:16]
}

/*
   ECB mode is deprecated and not included in golang crypto library.
*/
func decryptAes128Ecb(encryptedData []byte, key []byte) []byte {
	cipher, _ := aes.NewCipher(key)
	decrypted := make([]byte, len(encryptedData))
	size := 16
	for bs, be := 0, size; bs < len(encryptedData); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], encryptedData[bs:be])
	}
	return decrypted
}


func decryptNewFormatCredentials(cipher []byte, secret []byte) string {
	cipher = cipher[1:] // strip version
	cipher = cipher[4:] // strip iv length
	cipher = cipher[4:] // strip data length
	ivLength := 16      // TODO calculate this
	iv := cipher[:ivLength]
	cipher = cipher[ivLength:] //strip iv
	block, err := aes.NewCipher(secret)
	if err != nil{
		log.Fatalln(err)
	}
	mode := cipherLib.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipher, cipher)

	trimmed := strings.TrimSpace(string(cipher))

	// TODO strip PKCS7 padding with math not by strings.Replace()
	withoutPadding := strings.Replace(string(trimmed), string('\x05'), "", -1)
	withoutPadding = strings.Replace(string(withoutPadding), string('\x06'), "", -1)
	return withoutPadding
}
