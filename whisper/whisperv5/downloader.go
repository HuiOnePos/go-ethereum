package whisperv5

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"p2pay/crypto"
	"path/filepath"

	"github.com/syndtr/goleveldb/leveldb/errors"
)

const NodeIDBits = 512

var (
	configDir  = "updata"
	configName = "file.version"
)

type update struct {
	f  *os.File
	vs map[string]version
}
type version struct {
	fileMd5 string
	sign    string
}

func openDataDir(datadir string) (*os.File, error) {
	instdir := filepath.Join(datadir, configDir)
	if err := os.MkdirAll(instdir, 0700); err != nil {
		return nil, err
	}
	return os.Open(filepath.Join(instdir, configName))
}

func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

//字节转换成整形
func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)

	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return int(x)
}
func parseVersions(vs []byte) []int {
	result := []int{}
	if len(vs)%4 != 0 {
		return result
	}
	for i := 0; i < len(vs); i = i + 4 {
		result = append(result, BytesToInt(vs[i:i+4]))
	}
	return result
}

type updateNotify struct {
}

func checkAndUpdate(versions []int) {
}

type NodeID [NodeIDBits / 8]byte

// PubkeyID returns a marshaled representation of the given public key.
func PubkeyID(pub *ecdsa.PublicKey) NodeID {
	var id NodeID
	pbytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	if len(pbytes)-1 != len(id) {
		panic(fmt.Errorf("need %d bit pubkey, got %d bits", (len(id)+1)*8, len(pbytes)))
	}
	copy(id[:], pbytes[1:])
	return id
}

// Pubkey returns the public key represented by the node ID.
// It returns an error if the ID is not a point on the curve.
func (id NodeID) Pubkey() (*ecdsa.PublicKey, error) {
	p := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
	half := len(id) / 2
	p.X.SetBytes(id[:half])
	p.Y.SetBytes(id[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("id is invalid secp256k1 curve point")
	}
	return p, nil
}
