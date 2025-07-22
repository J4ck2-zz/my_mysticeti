package consensus

import (
	"WuKong/core"
	"WuKong/crypto"
	"bytes"
	"encoding/gob"
	"reflect"
	"strconv"
)

const (
	FLAG_YES uint8 = 0
	FLAG_NO  uint8 = 1
)

const (
	SPB_ONE_PHASE int8 = iota
	SPB_TWO_PHASE
)

const (
	VOTE_FLAG_YES int8 = iota
	VOTE_FLAG_NO
)

type Block struct {
	Author    core.NodeID
	Round     int
	PayLoads  []crypto.Digest
	Reference map[crypto.Digest]core.NodeID
	Nil		  bool
	TimeStamp int64
}

func (b *Block) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Block) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(b); err != nil {
		return err
	}
	return nil
}

func (b *Block) Hash() crypto.Digest {

	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(b.Author), 10))
	hasher.Add(strconv.AppendInt(nil, int64(b.Round), 10))
	hasher.Add(strconv.AppendInt(nil, int64(b.TimeStamp), 10))
	for _, p := range b.PayLoads {
		hasher.Add(p[:])
	}
	// for d, id := range b.Reference {
	// 	hasher.Add(d[:])
	// 	hasher.Add(strconv.AppendInt(nil, int64(id), 2))
	// }

	return hasher.Sum256(nil)
}

type SmvbaValue struct {
	Author     core.NodeID
	Epoch      int64
	Blockhashs []crypto.Digest
}

func (v *SmvbaValue) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (v *SmvbaValue) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(v); err != nil {
		return err
	}
	return nil
}

func (v *SmvbaValue) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 10))
	hasher.Add(strconv.AppendInt(nil, int64(v.Epoch), 10))
	for _, p := range v.Blockhashs {

		hasher.Add(p[:])
	}
	return hasher.Sum256(nil)
}

// ProposeMsg
type ProposeMsg struct {
	Author    core.NodeID
	Round     int
	B         *Block
	Signature crypto.Signature
}

func NewProposeMsg(
	Author core.NodeID,
	Round int,
	B *Block,
	sigService *crypto.SigService,
) (*ProposeMsg, error) {
	msg := &ProposeMsg{
		Author: Author,
		Round:  Round,
		B:      B,
	}
	if sig, err := sigService.RequestSignature(msg.Hash()); err != nil {
		return nil, err
	} else {
		msg.Signature = sig
		return msg, nil
	}
}

func (msg *ProposeMsg) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *ProposeMsg) Hash() crypto.Digest {

	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	digest := msg.B.Hash()
	hasher.Add(digest[:])
	return hasher.Sum256(nil)
}

func (msg *ProposeMsg) MsgType() int {
	return ProposeMsgType
}

func (msg *ProposeMsg) Module() string {
	return "consensus"
}

// ABA MSG
type ABAVal struct {
	Author     core.NodeID
	Round      int
	Slot       core.NodeID
	InRound    int
	Flag       uint8
	Signature  crypto.Signature
	LocalState uint8
}

func NewABAVal(Author core.NodeID, Round int, Slot core.NodeID, InRound int, Flag uint8, sigService *crypto.SigService, LocalStare uint8) (*ABAVal, error) {
	val := &ABAVal{
		Author:     Author,
		Round:      Round,
		Slot:       Slot,
		InRound:    InRound,
		Flag:       Flag,
		LocalState: LocalStare,
	}
	sig, err := sigService.RequestSignature(val.Hash())
	if err != nil {
		return nil, err
	}
	val.Signature = sig
	return val, nil
}

func (v *ABAVal) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *ABAVal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Round), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Slot), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.InRound), 2))
	hasher.Add([]byte{v.Flag})
	return hasher.Sum256(nil)
}

func (v *ABAVal) MsgType() int {
	return ABAValType
}

func (msg *ABAVal) Module() string {
	return "consensus"
}

type ABAMux struct {
	Author    core.NodeID
	Round     int
	Slot      core.NodeID
	InRound   int
	Flag      uint8
	Signature crypto.Signature
}

func NewABAMux(Author core.NodeID, Round int, Slot core.NodeID, InRound int, Flag uint8, sigService *crypto.SigService) (*ABAMux, error) {
	val := &ABAMux{
		Author:  Author,
		Round:   Round,
		Slot:    Slot,
		InRound: InRound,
		Flag:    Flag,
	}
	sig, err := sigService.RequestSignature(val.Hash())
	if err != nil {
		return nil, err
	}
	val.Signature = sig
	return val, nil
}

func (v *ABAMux) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *ABAMux) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Round), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Slot), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.InRound), 2))
	hasher.Add([]byte{v.Flag})
	return hasher.Sum256(nil)
}

func (v *ABAMux) MsgType() int {
	return ABAMuxType
}

func (msg *ABAMux) Module() string {
	return "consensus"
}

type CoinShare struct {
	Author  core.NodeID
	Round   int
	Slot    core.NodeID
	InRound int
	Share   crypto.SignatureShare
}

func NewCoinShare(Author core.NodeID, Round int, Slot core.NodeID, InRound int, sigService *crypto.SigService) (*CoinShare, error) {
	coin := &CoinShare{
		Author:  Author,
		Round:   Round,
		Slot:    Slot,
		InRound: InRound,
	}
	sig, err := sigService.RequestTsSugnature(coin.Hash())
	if err != nil {
		return nil, err
	}
	coin.Share = sig
	return coin, nil
}

func (c *CoinShare) Verify(committee core.Committee) bool {
	_ = committee.Name(c.Author)
	return c.Share.Verify(c.Hash())
}

func (c *CoinShare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(c.Round), 2))
	hasher.Add(strconv.AppendInt(nil, int64(c.Slot), 2))
	hasher.Add(strconv.AppendInt(nil, int64(c.InRound), 2))
	return hasher.Sum256(nil)
}

func (c *CoinShare) MsgType() int {
	return CoinShareType
}

func (msg *CoinShare) Module() string {
	return "consensus"
}

type ABAHalt struct {
	Author    core.NodeID
	Round     int
	Slot      core.NodeID
	InRound   int
	Flag      uint8
	Signature crypto.Signature
}

func NewABAHalt(Author core.NodeID, Round int, Slot core.NodeID, InRound int, Flag uint8, sigService *crypto.SigService) (*ABAHalt, error) {
	h := &ABAHalt{
		Author:  Author,
		Round:   Round,
		Slot:    Slot,
		InRound: InRound,
		Flag:    Flag,
	}
	sig, err := sigService.RequestSignature(h.Hash())
	if err != nil {
		return nil, err
	}
	h.Signature = sig
	return h, nil
}

func (h *ABAHalt) Verify(committee core.Committee) bool {
	pub := committee.Name(h.Author)
	return h.Signature.Verify(pub, h.Hash())
}

func (h *ABAHalt) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(h.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(h.Round), 2))
	hasher.Add(strconv.AppendInt(nil, int64(h.Slot), 2))
	hasher.Add(strconv.AppendInt(nil, int64(h.InRound), 2))
	hasher.Add([]byte{h.Flag})
	return hasher.Sum256(nil)
}

func (h *ABAHalt) MsgType() int {
	return ABAHaltType
}

func (msg *ABAHalt) Module() string {
	return "consensus"
}

// ReadyMsg
type ReadyMsg struct {
	Author    core.NodeID
	Proposer  core.NodeID
	BlockHash crypto.Digest
	Round     int
	Signature crypto.Signature
}

func NewReadyMsg(
	Author core.NodeID,
	Proposer core.NodeID,
	BlockHash crypto.Digest,
	Round int,
	sigService *crypto.SigService,
) (*ReadyMsg, error) {
	msg := &ReadyMsg{
		Author:    Author,
		Proposer:  Proposer,
		BlockHash: BlockHash,
		Round:     Round,
	}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *ReadyMsg) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *ReadyMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Proposer), 2))
	hasher.Add(msg.BlockHash[:])
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	return hasher.Sum256(nil)
}

func (msg *ReadyMsg) MsgType() int {
	return ReadyType
}

// RequestBlock
type RequestBlockMsg struct {
	Author    core.NodeID
	MissBlock []crypto.Digest
	Signature crypto.Signature
	ReqID     int
	Ts        int64
}

func NewRequestBlock(
	Author core.NodeID,
	MissBlock []crypto.Digest,
	ReqID int,
	Ts int64,
	sigService *crypto.SigService,
) (*RequestBlockMsg, error) {
	msg := &RequestBlockMsg{
		Author:    Author,
		MissBlock: MissBlock,
		ReqID:     ReqID,
		Ts:        Ts,
	}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *RequestBlockMsg) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *RequestBlockMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.ReqID), 2))
	for _, d := range msg.MissBlock {
		hasher.Add(d[:])
	}
	return hasher.Sum256(nil)
}

func (msg *RequestBlockMsg) MsgType() int {
	return RequestBlockType
}

func (msg *RequestBlockMsg) Module() string {
	return "consensus"
}

// ReplyBlockMsg
type ReplyBlockMsg struct {
	Author    core.NodeID
	Blocks    []*Block
	ReqID     int
	Signature crypto.Signature
}

func NewReplyBlockMsg(Author core.NodeID, B []*Block, ReqID int, sigService *crypto.SigService) (*ReplyBlockMsg, error) {
	msg := &ReplyBlockMsg{
		Author: Author,
		Blocks: B,
		ReqID:  ReqID,
	}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *ReplyBlockMsg) Verify(committee core.Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *ReplyBlockMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.ReqID), 2))
	return hasher.Sum256(nil)
}

func (msg *ReplyBlockMsg) MsgType() int {
	return ReplyBlockType
}

func (msg *ReplyBlockMsg) Module() string {
	return "consensus"
}

type LoopBackMsg struct {
	BlockHash crypto.Digest
}

func (msg *LoopBackMsg) Hash() crypto.Digest {
	return crypto.NewHasher().Sum256(msg.BlockHash[:])
}

func (msg *LoopBackMsg) MsgType() int {
	return LoopBackType
}

//sMvba

type SPBProposal struct {
	Author    core.NodeID
	B         *SmvbaValue
	Epoch     int64
	Round     int64
	Phase     int8
	Signature crypto.Signature
}

func NewSPBProposal(Author core.NodeID, B *SmvbaValue, Epoch, Round int64, Phase int8, sigService *crypto.SigService) (*SPBProposal, error) {
	proposal := &SPBProposal{
		Author: Author,
		B:      B,
		Epoch:  Epoch,
		Round:  Round,
		Phase:  Phase,
	}
	sig, err := sigService.RequestSignature(proposal.Hash())
	if err != nil {
		return nil, err
	}
	proposal.Signature = sig
	return proposal, nil
}

func (p *SPBProposal) Verify(committee core.Committee) bool {
	pub := committee.Name(p.Author)
	return p.Signature.Verify(pub, p.Hash())
}

func (p *SPBProposal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(p.Author), 2))
	hasher.Add(strconv.AppendInt(nil, p.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, p.Round, 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Phase), 2))
	if p.B != nil {
		d := p.B.Hash()
		hasher.Add(d[:])
	}
	return hasher.Sum256(nil)
}

func (*SPBProposal) MsgType() int {
	return SPBProposalType
}

func (*SPBProposal) Module() string {
	return "sMVBA"
}

type SPBVote struct {
	Author    core.NodeID
	Proposer  core.NodeID
	BlockHash crypto.Digest
	Epoch     int64
	Round     int64
	Phase     int8
	Signature crypto.Signature
}

func NewSPBVote(Author, Proposer core.NodeID, BlockHash crypto.Digest, Epoch, Round int64, Phase int8, sigService *crypto.SigService) (*SPBVote, error) {
	vote := &SPBVote{
		Author:    Author,
		Proposer:  Proposer,
		BlockHash: BlockHash,
		Epoch:     Epoch,
		Round:     Round,
		Phase:     Phase,
	}
	sig, err := sigService.RequestSignature(vote.Hash())
	if err != nil {
		return nil, err
	}
	vote.Signature = sig
	return vote, nil
}

func (v *SPBVote) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *SPBVote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
	hasher.Add(strconv.AppendInt(nil, v.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, v.Round, 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Phase), 2))

	hasher.Add(v.BlockHash[:])

	return hasher.Sum256(nil)
}

func (*SPBVote) MsgType() int {
	return SPBVoteType
}

func (*SPBVote) Module() string {
	return "sMVBA"
}

type Finish struct {
	Author    core.NodeID
	BlockHash crypto.Digest
	Epoch     int64
	Round     int64
	Signature crypto.Signature
}

func NewFinish(Author core.NodeID, BlockHash crypto.Digest, Epoch, Round int64, sigService *crypto.SigService) (*Finish, error) {
	finish := &Finish{
		Author:    Author,
		BlockHash: BlockHash,
		Epoch:     Epoch,
		Round:     Round,
	}
	sig, err := sigService.RequestSignature(finish.Hash())
	if err != nil {
		return nil, err
	}
	finish.Signature = sig
	return finish, nil
}

func (f *Finish) Verify(committee core.Committee) bool {
	pub := committee.Name(f.Author)
	return f.Signature.Verify(pub, f.Hash())
}

func (f *Finish) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(f.BlockHash[:])
	hasher.Add(strconv.AppendInt(nil, int64(f.Author), 2))
	hasher.Add(strconv.AppendInt(nil, f.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, f.Round, 2))
	return hasher.Sum256(nil)
}

func (*Finish) MsgType() int {
	return FinishType
}

func (*Finish) Module() string {
	return "sMVBA"
}

type Done struct {
	Author    core.NodeID
	Epoch     int64
	Round     int64
	Signature crypto.Signature
}

func NewDone(Author core.NodeID, epoch, round int64, sigService *crypto.SigService) (*Done, error) {
	done := &Done{
		Author: Author,
		Epoch:  epoch,
		Round:  round,
	}
	sig, err := sigService.RequestSignature(done.Hash())
	if err != nil {
		return nil, err
	}
	done.Signature = sig
	return done, nil
}

func (d *Done) Verify(committee core.Committee) bool {
	pub := committee.Name(d.Author)
	return d.Signature.Verify(pub, d.Hash())
}

func (d *Done) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(d.Author), 2))
	hasher.Add(strconv.AppendInt(nil, d.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, d.Round, 2))
	return hasher.Sum256(nil)
}

func (*Done) MsgType() int {
	return DoneType
}

func (*Done) Module() string {
	return "sMVBA"
}

type ElectShare struct {
	Author   core.NodeID
	Epoch    int64
	Round    int64
	SigShare crypto.SignatureShare
}

func NewElectShare(Author core.NodeID, epoch, round int64, sigService *crypto.SigService) (*ElectShare, error) {
	elect := &ElectShare{
		Author: Author,
		Epoch:  epoch,
		Round:  round,
	}
	sig, err := sigService.RequestTsSugnature(elect.Hash())
	if err != nil {
		return nil, err
	}
	elect.SigShare = sig
	return elect, nil
}

func (e *ElectShare) Verify(committee core.Committee) bool {
	_ = committee.Name(e.Author)
	return e.SigShare.Verify(e.Hash())
}

func (e *ElectShare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, e.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, e.Round, 2))
	return hasher.Sum256(nil)
}

func (*ElectShare) MsgType() int {
	return ElectShareType
}

func (*ElectShare) Module() string {
	return "sMVBA"
}

type Prevote struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	Flag      int8
	BlockHash crypto.Digest
	Signature crypto.Signature
}

func NewPrevote(Author, Leader core.NodeID, Epoch, Round int64, flag int8, BlockHash crypto.Digest, sigService *crypto.SigService) (*Prevote, error) {
	prevote := &Prevote{
		Author:    Author,
		Leader:    Leader,
		Epoch:     Epoch,
		Round:     Round,
		Flag:      flag,
		BlockHash: BlockHash,
	}
	sig, err := sigService.RequestSignature(prevote.Hash())
	if err != nil {
		return nil, err
	}
	prevote.Signature = sig
	return prevote, nil
}

func (p *Prevote) Verify(committee core.Committee) bool {
	pub := committee.Name(p.Author)
	return p.Signature.Verify(pub, p.Hash())
}

func (p *Prevote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(p.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Leader), 2))
	hasher.Add(strconv.AppendInt(nil, p.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, p.Round, 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Flag), 2))
	hasher.Add(p.BlockHash[:])
	return hasher.Sum256(nil)
}

func (*Prevote) MsgType() int {
	return PrevoteType
}

func (*Prevote) Module() string {
	return "sMVBA"
}

type FinVote struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Round     int64
	Flag      int8
	BlockHash crypto.Digest
	Signature crypto.Signature
}

func NewFinVote(Author, Leader core.NodeID, Epoch, Round int64, flag int8, BlockHash crypto.Digest, sigService *crypto.SigService) (*FinVote, error) {
	prevote := &FinVote{
		Author:    Author,
		Epoch:     Epoch,
		Round:     Round,
		Flag:      flag,
		BlockHash: BlockHash,
	}
	sig, err := sigService.RequestSignature(prevote.Hash())
	if err != nil {
		return nil, err
	}
	prevote.Signature = sig
	return prevote, nil
}

func (p *FinVote) Verify(committee core.Committee) bool {
	pub := committee.Name(p.Author)
	return p.Signature.Verify(pub, p.Hash())
}

func (p *FinVote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(p.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Leader), 2))
	hasher.Add(strconv.AppendInt(nil, p.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, p.Round, 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Flag), 2))
	hasher.Add(p.BlockHash[:])
	return hasher.Sum256(nil)
}

func (*FinVote) MsgType() int {
	return FinVoteType
}

func (*FinVote) Module() string {
	return "sMVBA"
}

type Halt struct {
	Author    core.NodeID
	Epoch     int64
	Round     int64
	Leader    core.NodeID
	BlockHash crypto.Digest
	Signature crypto.Signature
}

func NewHalt(Author, Leader core.NodeID, BlockHash crypto.Digest, Epoch, Round int64, sigService *crypto.SigService) (*Halt, error) {
	h := &Halt{
		Author:    Author,
		Epoch:     Epoch,
		Round:     Round,
		Leader:    Leader,
		BlockHash: BlockHash,
	}
	sig, err := sigService.RequestSignature(h.Hash())
	if err != nil {
		return nil, err
	}
	h.Signature = sig
	return h, nil
}

func (h *Halt) Verify(committee core.Committee) bool {
	pub := committee.Name(h.Author)
	return h.Signature.Verify(pub, h.Hash())
}

func (h *Halt) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(h.Author), 2))
	hasher.Add(strconv.AppendInt(nil, h.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(h.Leader), 2))
	hasher.Add(h.BlockHash[:])
	return hasher.Sum256(nil)
}

func (*Halt) MsgType() int {
	return HaltType
}

func (*Halt) Module() string {
	return "sMVBA"
}

const (
	ProposeMsgType int = iota
	ReadyType
	RequestBlockType
	ReplyBlockType
	LoopBackType
	ABAValType
	ABAMuxType
	CoinShareType
	ABAHaltType

	SPBProposalType
	SPBVoteType
	FinishType
	DoneType
	ElectShareType
	PrevoteType
	FinVoteType
	HaltType
)

var DefaultMsgTypes = map[int]reflect.Type{
	ProposeMsgType:   reflect.TypeOf(ProposeMsg{}),
	ReadyType:        reflect.TypeOf(ReadyMsg{}),
	RequestBlockType: reflect.TypeOf(RequestBlockMsg{}),
	ReplyBlockType:   reflect.TypeOf(ReplyBlockMsg{}),
	LoopBackType:     reflect.TypeOf(LoopBackMsg{}),
	ABAValType:       reflect.TypeOf(ABAVal{}),
	ABAMuxType:       reflect.TypeOf(ABAMux{}),
	CoinShareType:    reflect.TypeOf(CoinShare{}),
	ABAHaltType:      reflect.TypeOf(ABAHalt{}),

	SPBProposalType: reflect.TypeOf(SPBProposal{}),
	SPBVoteType:     reflect.TypeOf(SPBVote{}),
	FinishType:      reflect.TypeOf(Finish{}),
	DoneType:        reflect.TypeOf(Done{}),
	ElectShareType:  reflect.TypeOf(ElectShare{}),
	PrevoteType:     reflect.TypeOf(Prevote{}),
	FinVoteType:     reflect.TypeOf(FinVote{}),
	HaltType:        reflect.TypeOf(Halt{}),
}
