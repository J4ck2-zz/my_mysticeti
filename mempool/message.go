package mempool

import (
	"WuKong/core"
	"WuKong/crypto"
	"WuKong/pool"
	"bytes"
	"encoding/gob"
	"reflect"
	"strconv"
)

type Payload struct {
	Proposer  core.NodeID
	Batch     pool.Batch
	Signature crypto.Signature
}

func NewPload(proposer core.NodeID, Batch pool.Batch, sigService *crypto.SigService) (*Payload, error) {
	payload := &Payload{
		Proposer: proposer,
		Batch:    Batch,
	}
	sig, err := sigService.RequestSignature(payload.Hash())
	if err != nil {
		return nil, err
	}
	payload.Signature = sig
	return payload, nil
}

func (b *Payload) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Payload) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(b); err != nil {
		return err
	}
	return nil
}

func (b *Payload) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(b.Proposer), 2))
	hasher.Add(strconv.AppendInt(nil, int64(b.Batch.ID), 2))
	for _, tx := range b.Batch.Txs {
		hasher.Add(tx)
	}
	return hasher.Sum256(nil)
}

func (msg *Payload) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Proposer), msg.Hash())
}

type OwnPayloadMsg struct {
	Payload *Payload
}

func (own *OwnPayloadMsg) MsgType() int {
	return OwnPayloadType
}

func (own *OwnPayloadMsg) Module() string {
	return "mempool"
}

type OtherPayloadMsg struct {
	Payload *Payload
}

func (o *OtherPayloadMsg) MsgType() int {
	return OtherPayloadType
}

func (o *OtherPayloadMsg) Module() string {
	return "mempool"
}

type ReplyPayloadRequestMsg struct {
	Payload []*Payload
	Author  core.NodeID
}

func (r *ReplyPayloadRequestMsg) MsgType() int {
	return ReplyPayloadRequestType
}

func (r *ReplyPayloadRequestMsg) Module() string {
	return "mempool"
}

type RequestPayloadMsg struct {
	Type    uint8 //0代表方案处理请求，1代表commit处理请求
	Digests []crypto.Digest
	Author  core.NodeID
	ReqId   int
}

func (r *RequestPayloadMsg) MsgType() int {
	return RequestPayloadType
}

func (r *RequestPayloadMsg) Module() string {
	return "mempool"
}

type MakeConsensusBlockMsg struct {
	Payloads chan []crypto.Digest
}

func (r *MakeConsensusBlockMsg) MsgType() int {
	return MakeBlockType
}

func (r *MakeConsensusBlockMsg) Module() string {
	return "connect"
}

type VerifyStatus int

const (
	OK VerifyStatus = iota
	Wait
	Reject
)

type VerifyBlockMsg struct { //这个的作用是验证共识区块是否已经被收到
	//B      *consensus.Block
	Proposer           core.NodeID
	Epoch              int64
	Payloads           []crypto.Digest
	ConsensusBlockHash crypto.Digest
	Sender             chan VerifyStatus // 0:ok 1:wait 2:reject
}

func (*VerifyBlockMsg) MsgType() int {
	return VerifyBlockType
}
func (*VerifyBlockMsg) Module() string {
	return "connect"
}

type CleanBlockMsg struct {
	Digests []crypto.Digest
}

func (l *CleanBlockMsg) MsgType() int {
	return CleanBlockType
}

func (l *CleanBlockMsg) Module() string {
	return "connect"
}

type SyncBlockMsg struct {
	Missing []crypto.Digest //consensus中缺少的块
	Author  core.NodeID     //consensublock的作者
	//Block       *consensus.Block //这个是和大家同步某个区块，但是感觉也不能放到这里
	Epoch              int64
	ConsensusBlockHash crypto.Digest
}

func (s *SyncBlockMsg) MsgType() int {
	return SyncBlockType
}
func (s *SyncBlockMsg) Module() string {
	return "mempool"
}

type SyncCleanUpBlockMsg struct {
	Epoch uint64
}

func (s *SyncCleanUpBlockMsg) MsgType() int {
	return SyncCleanUpBlockType
}

func (s *SyncCleanUpBlockMsg) Module() string {
	return "mempool"
}

type MempoolValidator interface {
	Verify(core.Committee) bool
}

type LoopBackMempoolMsg struct {
	BlockHash crypto.Digest
}

func (msg *LoopBackMempoolMsg) Hash() crypto.Digest {
	return crypto.NewHasher().Sum256(msg.BlockHash[:])
}

func (msg *LoopBackMempoolMsg) MsgType() int {
	return LoopBackMempoolType
}

func (msg *LoopBackMempoolMsg) Module() string {
	return "consensus"
}

const (
	OwnPayloadType int = iota + 17
	OtherPayloadType
	RequestPayloadType
	MakeBlockType
	VerifyBlockType
	CleanBlockType
	SyncBlockType
	SyncCleanUpBlockType
	LoopBackMempoolType
	ReplyPayloadRequestType
)

var DefaultMessageTypeMap = map[int]reflect.Type{
	OwnPayloadType:          reflect.TypeOf(OwnPayloadMsg{}),
	OtherPayloadType:        reflect.TypeOf(OtherPayloadMsg{}),
	RequestPayloadType:      reflect.TypeOf(RequestPayloadMsg{}),
	MakeBlockType:           reflect.TypeOf(MakeConsensusBlockMsg{}),
	VerifyBlockType:         reflect.TypeOf(VerifyBlockMsg{}),
	CleanBlockType:          reflect.TypeOf(CleanBlockMsg{}),
	SyncBlockType:           reflect.TypeOf(SyncBlockMsg{}),
	SyncCleanUpBlockType:    reflect.TypeOf(SyncCleanUpBlockMsg{}),
	LoopBackMempoolType:     reflect.TypeOf(LoopBackMempoolMsg{}),
	ReplyPayloadRequestType: reflect.TypeOf(ReplyPayloadRequestMsg{}),
}
