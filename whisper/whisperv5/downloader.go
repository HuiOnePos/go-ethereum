package whisperv5

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"p2pay/common"
	"p2pay/common/hexutil"
	"p2pay/crypto"
	"p2pay/crypto/sha3"
	"p2pay/log"
	"p2pay/rlp"
	"path/filepath"
	"sync"
	"time"
)

var (
	configDir  = "update"
	configName = "file.version"
	cacheDir   = "cache"
)

const (
	upDataCancle     = byte(0)
	upDataQuery      = byte(1)
	upDataVersions   = byte(2)
	upDataFileHeader = byte(3)
	upDataFileData   = byte(4)
	upDataCallback   = byte(5)
	upDataEnd        = byte(100)
	upDataTimeOut    = byte(101)
)

type update struct {
	Vs   []version
	hash []byte
	Num  *big.Int
}
type version struct {
	FileMd5 string
	Name    string
	Size    *big.Int
}

func (u *update) toBytes() []byte {
	if u.Num == nil {
		u.Num = big.NewInt(0)
	}
	b, _ := rlp.EncodeToBytes(u)
	return append(u.hash, b...)
}
func (u *update) hashString() string {
	return hexutil.Encode(u.hash)
}
func (u *update) save(path string) error {
	f, err := openDataDir(filepath.Join(path, configDir), configName)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := rlp.EncodeToBytes(u)
	f.Write(u.hash)
	f.Write(b)
	return err
}

type MsgWithPeer struct {
	d []byte
	p *Peer
}

func (m *MsgWithPeer) parseVersions() *update {
	version := &update{Num: big.NewInt(0), Vs: []version{}}

	if len(m.d) < 70 {
		return version
	}
	var hashkey []byte
	hl := BytesToInt(m.d[:4])
	signkey := m.d[4 : 4+hl]
	mdl := len(m.d)
	for n := 4 + hl; n < mdl; n += 1024 {
		if n+1024 > mdl {
			hashkey = rlpHash([][]byte{hashkey, m.d[n:mdl]})
		} else {
			hashkey = rlpHash([][]byte{hashkey, m.d[n : n+1024]})
		}
	}
	if !verifySign(hashkey, signkey) {
		log.Error("version sign error")
		return version
	}
	if rlp.DecodeBytes(m.d[4+hl:], version) != nil {
		return version
	}
	version.hash = append(m.d[:4+hl])
	return version
}

type updateWorker struct {
	versions *update
	updating bool
	path     string
	wh       *Whisper
	wg       sync.WaitGroup
	rec      *receive
}
type receive struct {
	versions *update
	files    map[string]string
	ok       map[string]int64
	up       map[string]int64
	f        string
	fs       int64
	signkey  string
	fwrite   *os.File
	p        *Peer
	close    chan struct{}
	rec      chan recdata
	path     string
	work     *updateWorker
}

func (r *receive) getUpFileInfo(versions *update) {
	oldfiles := map[string]string{}
	for _, f := range versions.Vs {
		oldfiles[f.Name] = f.FileMd5
	}
	for _, f := range r.versions.Vs {
		if md5, ok := oldfiles[f.Name]; !ok || md5 != f.FileMd5 {
			r.up[f.Name] = f.Size.Int64()
		}
		r.files[f.Name] = f.FileMd5
	}
}

func (r *receive) start() {
	var data recdata
	var err error
	for {
		select {
		case data = <-r.rec:
			switch data.tag {
			case upDataFileHeader:
				if err = r.recFileHeader(data.d); err != nil {
					r.stop(upDataCancle)
				} else {
					r.send2P2p([]byte{upDataFileHeader, upDataCallback})
				}
			case upDataFileData:
				if err = r.recFileData(data.d); err != nil {
					r.stop(upDataCancle)
				} else {
					r.send2P2p([]byte{upDataFileData, upDataCallback})
				}
			case upDataCallback:
				switch data.d[0] {
				case upDataVersions:
					r.sendFileHeader()
				case upDataFileHeader:
					r.sendFileData()
				case upDataFileData:
					r.sendFileData()
				}
			}
		case <-r.close:
			return
		case <-time.Tick(1 * time.Minute):
			r.send2P2p([]byte{upDataCancle})
			r.stop(upDataTimeOut)
			return
		}
	}
}
func (r *receive) end() {
	log.Info("receive end", "files", len(r.ok))
	if len(r.up) > 0 {
		log.Error("receive files nums err", "have", len(r.ok), "out", len(r.up))
	}
	fromdir, todir := filepath.Join(r.work.path, cacheDir), filepath.Join(r.work.path, configDir)
	for f, _ := range r.ok {
		os.Rename(filepath.Join(fromdir, f), filepath.Join(todir, f))
	}
	r.versions.save(r.work.path)
	r.work.versions = r.versions
	r.stop(upDataEnd)
}
func (r *receive) sendFileHeader() {
	if r.f != "" || r.fs != 0 || r.fwrite != nil {
		return
	}
	if len(r.up) == 0 {
		//发送结束
		r.send2P2p([]byte{upDataEnd})
		r.stop(upDataEnd)
		return
	}
	for r.f, _ = range r.up {
		break
	}
	log.Info("start send file", "name", r.f, "size", r.up[r.f], "md5", r.files[r.f])
	var err error
	//打开文件
	r.fwrite, err = openDataDir(filepath.Join(r.path, configDir), r.f)
	if err != nil {
		log.Error("send file fail", "name", r.f, "err", err)
		r.send2P2p([]byte{upDataCancle})
		r.stop(upDataCancle)
	}
	r.send2P2p(append([]byte(r.f), upDataFileHeader))
}
func (r *receive) sendFileData() {
	//发送一个新文件
	if r.up[r.f] == r.fs {
		log.Info("send file succ", "name", r.f)
		delete(r.up, r.f)
		r.fwrite.Close()
		r.fwrite = nil
		r.f = ""
		r.fs = 0
		r.sendFileHeader()
		return
	}
	if r.fwrite == nil {
		return
	}
	//每次读取1M,记录读取位置
	filedata := make([]byte, 1024*1024)
	n, e := r.fwrite.ReadAt(filedata, r.fs)
	if e != nil && e != io.EOF {
		r.fwrite.Close()
		log.Error("send file data", "name", r.f, "err", e)
		r.send2P2p([]byte{upDataCancle})
		r.stop(upDataCancle)
	}
	r.fs += int64(n)
	//发送文件数据
	r.send2P2p(append(filedata[:n], upDataFileData))

}
func (r *receive) stop(msg byte) {
	if msg != upDataEnd {
		log.Warn("rec stop", "message", msg)
		r.send2P2p([]byte{msg})
	}
	if r.fwrite != nil {
		r.fwrite.Close()
	}
	close(r.close)
	close(r.rec)
	r = nil
	return
}
func (r *receive) recFileData(data []byte) error {
	//发送接收文件数据的回执
	if r.f == "" || r.fs == r.up[r.f] || r.fwrite == nil {
		return fmt.Errorf("file header error")
	}
	if r.fs+int64(len(data)) > r.up[r.f] {
		return fmt.Errorf("file size error")
	}
	n, e := r.fwrite.Write(data)
	if e != nil {
		return fmt.Errorf("write file err", e)
	}
	r.fs += int64(n)
	r.signkey = hexutil.Encode(rlpHash([]interface{}{r.signkey, data}))
	if r.fs == r.up[r.f] {
		if r.signkey != r.files[r.f] {
			log.Error("receive file md5 fail", "have", r.signkey, "want", r.files[r.f])
			os.RemoveAll(r.fwrite.Name())
			return fmt.Errorf("receive file md5 err")
		}
		log.Info("receive file succ", "name", r.f)
		delete(r.up, r.f)
		//接受完成，清空
		r.ok[r.f] = r.fs
		r.signkey = ""
		r.f = ""
		r.fs = 0
		r.fwrite.Close()
		r.fwrite = nil
	}
	return nil
}
func (r *receive) recFileHeader(data []byte) error {
	file := string(data)
	if _, ok := r.up[file]; !ok {
		return fmt.Errorf("no upfile")
	}
	r.f = file
	r.fwrite, _ = openDataDir(filepath.Join(r.path, cacheDir), r.f)
	log.Info("start receive file", "name", r.f, "size", r.up[r.f], "md5", r.files[r.f])
	return nil
}

type recdata struct {
	tag byte
	d   []byte
}

func (r *receive) send2P2p(data []byte) {
	pubKey, _ := r.p.peer.ID().Pubkey()
	params := &MessageParams{
		Src:     r.work.wh.privateKeys["node"],
		Dst:     pubKey,
		Payload: data,
		Topic:   updateDataTopic,
		ST:      SignTypeAsym,
	}

	msg, err := NewSentMessage(params)
	if err != nil {
		log.Warn("update msg fail", "error", err)
	}
	envelop, err := msg.Wrap(params)
	if err != nil {
		log.Warn("update msg fail", "error", err)
	}
	err = r.work.wh.SendP2PDirect(r.p, envelop)
	if err != nil {
		log.Warn("update msg fail", "error", err)
	}
}

func (u *updateWorker) update(data MsgWithPeer) {
	l := len(data.d)
	tag := data.d[l-1:][0]
	data.d = data.d[:l-1]
	switch tag {
	case upDataQuery:
		//check
		u.check(data)
	case upDataVersions:
		u.startReceive(data)
	case upDataFileHeader, upDataFileData, upDataCallback:
		if u.rec != nil {
			u.rec.rec <- recdata{tag, data.d}
		}
	case upDataCancle:
		u.rec.stop(upDataEnd)
	case upDataEnd:
		u.rec.end()

	default:
		log.Error("not found update tag", "tag", tag)
	}
}
func (u *updateWorker) startReceive(data MsgWithPeer) {
	u.wg.Wait()
	u.rec = &receive{p: data.p, files: map[string]string{}, ok: map[string]int64{}, up: map[string]int64{}, work: u}
	u.rec.versions = data.parseVersions()
	if u.rec.versions.Num.Cmp(u.versions.Num) <= 0 {
		log.Warn("receive new version,received is old", "rec ver", u.rec.versions.Num, "loc ver", u.versions.Num)
		u.rec = nil
		u.rec.send2P2p([]byte{upDataCancle})
		return
	}

	u.rec.path = u.path
	u.rec.getUpFileInfo(u.versions)
	if len(u.rec.up) == 0 {
		u.rec = nil
		u.rec.send2P2p([]byte("closed"))
		return
	}
	/*u.rec.send = make(chan recdata)*/
	u.rec.close = make(chan struct{})
	u.rec.rec = make(chan recdata)

	//清空cache目录
	os.RemoveAll(filepath.Join(u.path, cacheDir))
	go u.receive()
	//callback
	u.rec.send2P2p([]byte{upDataVersions, upDataCallback})
}
func (u *updateWorker) receive() {
	defer func() {
		/*u.rec = nil*/
		u.wg.Done()
	}()
	u.wg.Add(1)
	u.rec.start()
}

func (u *updateWorker) check(data MsgWithPeer) {
	u.wg.Wait()
	versions := data.parseVersions()
	if u.versions.hashString() == versions.hashString() {
		log.Info("check sys version ok", "peer", data.p.peer.String(), "version", versions.Num)
	} else if versions.Num != nil {
		if u.versions.Num.Cmp(versions.Num) > 0 {
			log.Info("start updating")
			u.startSend(versions, data.p)
		}
	}
}
func (u *updateWorker) startSend(versions *update, p *Peer) {
	u.rec = &receive{p: p, files: map[string]string{}, ok: map[string]int64{}, up: map[string]int64{}, work: u}
	u.rec.versions = u.versions

	u.rec.path = u.path
	u.rec.getUpFileInfo(versions)
	if len(u.rec.up) == 0 {
		u.rec = nil
		u.rec.send2P2p([]byte{upDataCancle})
		return
	}
	/*u.rec.send = make(chan recdata)*/
	u.rec.close = make(chan struct{})
	u.rec.rec = make(chan recdata)
	u.rec.send2P2p(append(u.versions.toBytes(), upDataVersions))

	go u.receive()
}

func (u *updateWorker) loadVersions() (err error) {
	u.versions = &update{Num: big.NewInt(0), Vs: []version{}}
	f, err := openDataDir(filepath.Join(u.path, configDir), configName)
	if err != nil {
		return err
	}
	defer f.Close()
	b := make([]byte, 1024)
	var n int64
	var tn int
	var data []byte
	var hashkey, signkey []byte
	var getsign bool

	for {
		tn, _ = f.ReadAt(b, n)
		if !getsign && tn > 100 {
			signlen := BytesToInt(b[:4])
			signkey = append(hashkey, b[4:signlen+4]...)
			getsign = true
			n = n + 4 + int64(signlen)
		} else {
			data = append(data, b[:tn]...)
			hashkey = rlpHash([][]byte{hashkey, b[:tn]})
			if tn < 1024 {
				break
			}
			n += int64(tn)
		}
	}
	if !verifySign(hashkey, signkey) {
		return fmt.Errorf("versions info file sign error")
	}
	/*u.versions = &update{}*/
	if err = rlp.DecodeBytes(data, u.versions); err != nil {
		return
	}
	u.versions.hash = append(IntToBytes(len(signkey)), signkey...)
	return
}

var defaultUpdateSignPublic *ecdsa.PublicKey
var defaultSignAddr = common.HexToAddress("0x06df07ca8a760cec675115fb0e9c17582fbcee49")

func newUpdateWork(path string, wh *Whisper) (updatework *updateWorker, err error) {
	updatework = &updateWorker{
		path: path,
		wg:   sync.WaitGroup{},
		wh:   wh,
	}
	err = updatework.loadVersions()
	return
}

func openDataDir(datadir, filename string) (*os.File, error) {
	if err := os.MkdirAll(datadir, 0700); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(datadir, filename), os.O_CREATE|os.O_RDWR, os.ModePerm)
}

func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)

	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return int(x)
}

func verifySign(hash, key []byte) bool {
	pub, err := crypto.SigToPub(hash, key)
	if err != nil {
		return false
	}
	return crypto.PubkeyToAddress(*pub) == defaultSignAddr
}

func rlpHash(x interface{}) []byte {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	return hw.Sum(nil)
}
