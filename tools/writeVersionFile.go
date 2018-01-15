package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"p2pay/accounts/keystore"
	"p2pay/common/hexutil"
	"p2pay/crypto"
	"p2pay/crypto/sha3"
	"p2pay/rlp"
)

var filepath = "/Users/panjjo/Library/Ethereum/update/file.version"
var accountFile = "/Users/panjjo/Desktop/panjinjie"
var pwd = "panjinjie!@"
var files = map[string]string{
	"geth": "/Users/panjjo/Library/Ethereum/update/geth",
	/*"test": "/Users/panjjo/Library/Ethereum/update/test",
	"abc":  "/Users/panjjo/Library/Ethereum/update/abc",*/
}

type update struct {
	Vs  []version
	Num *big.Int
}
type version struct {
	FileMd5 string
	Name    string
	Size    *big.Int
}

func main() {
	update := update{
		Vs: []version{
		/*version{FileMd5: []byte("abdfdfasdfdfasdfdfadfafcdeffdasdfadfasdfdghdidf"), Name: "geth", Size: big.NewInt(2048)},*/
		},
		Num: big.NewInt(23),
	}
	var size int64
	var signkey string
	for name, fp := range files {
		size = 0
		signkey = ""
		filedata := make([]byte, 1024*1024)
		for {
			f, err := os.Open(fp)
			n, err := f.ReadAt(filedata, size)
			fmt.Println(err)
			signkey = hexutil.Encode(rlpHash([]interface{}{signkey, filedata[:n]}))
			fmt.Println(signkey)
			size += int64(n)
			if n < 1024 || err == io.EOF {
				break
			}
		}
		update.Vs = append(update.Vs, version{signkey, name, big.NewInt(size)})
	}
	b, err := rlp.EncodeToBytes(update)
	var hashkey []byte
	for {
		if len(b) < 1024 {
			hashkey = rlpHash([][]byte{hashkey, b})
			break
		} else {
			hashkey = rlpHash([][]byte{hashkey, b[:1024]})
		}
		b = b[1024:]
	}
	key, err := readAccount()
	sign, err := crypto.Sign(hashkey, key.PrivateKey)
	f, err := os.OpenFile(filepath, os.O_RDWR|os.O_CREATE, os.ModePerm)
	fmt.Println(err)
	fmt.Println(f.Write(IntToBytes(len(sign))))
	fmt.Println(f.Write(sign))
	fmt.Println(f.Write(b))
	f.Close()
}
func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func readAccount() (*keystore.Key, error) {
	keyjson, err := ioutil.ReadFile(accountFile)
	if err != nil {
		return nil, err
	}
	return keystore.DecryptKey(keyjson, pwd)
}
func rlpHash(x interface{}) []byte {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	return hw.Sum(nil)
}
