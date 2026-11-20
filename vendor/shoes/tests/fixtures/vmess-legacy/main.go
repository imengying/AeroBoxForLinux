package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

func main() {
	user, _ := hex.DecodeString("00000000000040008000000000000001")
	key := md5.Sum(append(append([]byte{}, user...), []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...))
	alter := md5.Sum(append(append([]byte{}, user...), []byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81")...))
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], 1700000000)
	auth := hmac.New(md5.New, alter[:])
	auth.Write(timestamp[:])
	input := []byte{}
	for i := 0; i < 4; i++ {
		input = append(input, timestamp[:]...)
	}
	iv := md5.Sum(input)
	header := make([]byte, 57)
	for i := range header {
		header[i] = byte(i)
	}
	block, _ := aes.NewCipher(key[:])
	cipher.NewCFBEncrypter(block, iv[:]).XORKeyStream(header, header)
	fmt.Printf("%x%x\n", auth.Sum(nil), header)
}
