package whisperv5

import (
	"bytes"
	"encoding/binary"
)

var datadir string
var (
	ethVersion = 1
	apiVersion = 234
	jsVersion  = 2034523
	/*ethUpdateType = 1
	jsUpdateType  = 2
	apiUpdateType = 255*/
)

func getVersions() []byte {
	return append(IntToBytes(ethVersion), append(IntToBytes(apiVersion), IntToBytes(jsVersion)...)...)
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
