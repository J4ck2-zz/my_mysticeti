package consensus

import (
	"WuKong/core"
	"WuKong/crypto"
	"WuKong/logger"
	"WuKong/mempool"
	"WuKong/pool"
	"WuKong/store"
	"sync"
	"time"
)

type Core struct {
	nodeID     core.NodeID
	round      int
	committee  core.Committee
	parameters core.Parameters
	txpool     *pool.Pool
	transmitor *core.Transmitor
	sigService *crypto.SigService
	store      *store.Store
	retriever  *Retriever
	commitor   *Commitor
	localDAG   *LocalDAG

	MemPool            *mempool.Mempool
	mempoolbackchannel chan crypto.Digest
	pendingPayloads    map[crypto.Digest]chan *mempool.Payload // digest -> waiting channel
	muPending          *sync.RWMutex
	connectChannel     chan core.Message

	loopBackChannel chan *Block
	loopDigests     chan crypto.Digest
	commitChannel   chan<- *Block
	proposedFlag    map[int]struct{}

	delayRoundCh chan int
	notifyPLoad  chan crypto.Digest
}

func NewCore(
	nodeID core.NodeID,
	committee core.Committee,
	parameters core.Parameters,
	txpool *pool.Pool,
	transmitor *core.Transmitor,
	store *store.Store,
	sigService *crypto.SigService,
	commitChannel chan<- *Block,

	mempoolbackchannel chan crypto.Digest,
	connectChannel chan core.Message,
	pool *mempool.Mempool,
) *Core {
	loopBackChannel := make(chan *Block, 1_000)

	loopDigest := make(chan crypto.Digest, 100)

	notifypload := make(chan crypto.Digest, 100)

	// Sync := mempool.NewSynchronizer(nodeID, transmitor, mempoolbackchannel, parameters, store)
	// pool := mempool.NewMempool(nodeID, committee, parameters, sigService, store, txpool, transmitor, Sync)
	corer := &Core{
		nodeID:          nodeID,
		committee:       committee,
		round:           0,
		parameters:      parameters,
		txpool:          txpool,
		transmitor:      transmitor,
		sigService:      sigService,
		store:           store,
		loopBackChannel: loopBackChannel,
		loopDigests:     loopDigest,
		commitChannel:   commitChannel,

		MemPool:            pool,
		pendingPayloads:    make(map[crypto.Digest]chan *mempool.Payload),
		muPending:          &sync.RWMutex{},
		mempoolbackchannel: mempoolbackchannel,
		connectChannel:     connectChannel,

		localDAG:     NewLocalDAG(store, committee),
		proposedFlag: make(map[int]struct{}),

		delayRoundCh: make(chan int, 100),
		notifyPLoad:  notifypload,
	}

	corer.retriever = NewRetriever(nodeID, store, transmitor, sigService, parameters, loopBackChannel, loopDigest, corer.localDAG)
	corer.commitor = NewCommitor(corer.localDAG, store, commitChannel, connectChannel, notifypload)

	return corer
}

func GetPayload(s *store.Store, digest crypto.Digest) (*mempool.Payload, error) {
	value, err := s.Read(digest[:])

	if err == store.ErrNotFoundKey {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	b := &mempool.Payload{}
	if err := b.Decode(value); err != nil {
		return nil, err
	}
	return b, err
}

func storeBlock(store *store.Store, block *Block) error {
	key := block.Hash()
	if val, err := block.Encode(); err != nil {
		return err
	} else {
		store.Write(key[:], val)
		return nil
	}
}

func getBlock(store *store.Store, digest crypto.Digest) (*Block, error) {
	block := &Block{}
	data, err := store.Read(digest[:])
	if err != nil {
		return nil, err
	}
	if err := block.Decode(data); err != nil {
		return nil, err
	}
	return block, nil
}

func isInStore(store *store.Store, digest crypto.Digest) bool {
	_, err := store.Read(digest[:])

	return err == nil
}

func (corer *Core) checkReference(block *Block) (bool, []crypto.Digest, []crypto.Digest) {
	var temp []crypto.Digest
	var localMissBlocks []crypto.Digest
	var remoteMissBlocks []crypto.Digest
	for d := range block.Reference {
		temp = append(temp, d)
	}
	ok, missDeigest := corer.localDAG.IsReceived(temp...)

	if !ok {
		for _, d := range missDeigest {
			if isInStore(corer.store, d) {
				localMissBlocks = append(localMissBlocks, d)
			} else {
				remoteMissBlocks = append(remoteMissBlocks, d)
			}
		}
		return ok, remoteMissBlocks, localMissBlocks
	}

	return ok, missDeigest, localMissBlocks
}

// func (corer *Core) messageFilter(epoch int64) bool {
// 	return corer.Epoch > epoch
// }

/*********************************Protocol***********************************************/
func (corer *Core) generatorBlock(round int) *Block {
	logger.Debug.Printf("procesing generatorBlock round %d \n", round)

	var block *Block
	if _, ok := corer.proposedFlag[round]; !ok {
		referencechan := make(chan []crypto.Digest)
		msg := &mempool.MakeConsensusBlockMsg{
			Payloads: referencechan,
		}
		corer.connectChannel <- msg
		payloads := <-referencechan
		var nil bool
		if len(payloads) == 1 {
			payload, _ := GetPayload(corer.store, payloads[0])
			if payload.Batch.ID == -1 {
				nil = true
			} else {
				nil = false
			}
		} else {
			nil = false
		}
		if round == 0 {
			block = &Block{
				Author:    corer.nodeID,
				Round:     round,
				PayLoads:  payloads,
				Nil:       nil,
				Reference: make(map[crypto.Digest]core.NodeID),
				TimeStamp: time.Now().Unix(),
			}
		} else {
			reference := corer.localDAG.GetRoundReceivedBlocks(round - 1)
			if len(reference) >= corer.committee.HightThreshold() {
				block = &Block{
					Author:    corer.nodeID,
					Round:     round,
					PayLoads:  payloads,
					Nil:       nil,
					Reference: reference,
					//Reference: make(map[crypto.Digest]core.NodeID),
					TimeStamp: time.Now().Unix(),
				}
			}
		}
	}

	//BenchMark Log
	if block != nil {
		corer.proposedFlag[round] = struct{}{}
		logger.Info.Printf("create Block round %d node %d \n", block.Round, block.Author)
	}

	return block

}

func (corer *Core) handlePropose(propose *ProposeMsg) error {
	logger.Debug.Printf("procesing block propose round %d node %d \n", propose.Round, propose.Author)

	//Step 1: verify signature
	if !propose.Verify(corer.committee) {
		return ErrSignature(propose.MsgType(), propose.Round, int(propose.Author))
	}

	//Step 2: store Block
	if err := storeBlock(corer.store, propose.B); err != nil {
		return err
	}

	//Step 3: check reference
	if ok, miss, localMiss := corer.checkReference(propose.B); !ok {
		//retrieve miss block
		corer.retriever.requestBlocks(miss, localMiss, propose.Author, propose.B.Hash())

		if status := corer.checkPayloads(propose.B); status != mempool.OK {
			logger.Debug.Printf("[round-%d-node-%d] not receive all payloads\n", propose.Round, propose.Author)
		}
		if localMiss != nil {
			return ErrLocalReference(propose.MsgType(), propose.Round, int(propose.Author), len(miss), len(localMiss))
		}
		return ErrReference(propose.MsgType(), propose.Round, int(propose.Author))
	}

	//Step 4:check payloads
	if status := corer.checkPayloads(propose.B); status != mempool.OK {
		return ErrLossPayloads(propose.Round, int(propose.Author))
	}

	// corer.connectChannel <- &mempool.CleanBlockMsg{
	// 	Digests: propose.B.PayLoads,
	// }

	//Step 5: write to dag
	if err := corer.handleOutPut(propose.B.Round, propose.B.Author, propose.B.Hash(), propose.B.Reference); err != nil {
		return err
	}

	return nil
}

func (corer *Core) checkPayloads(block *Block) mempool.VerifyStatus {
	if block.Nil {
		return mempool.OK
	}

	msg := &mempool.VerifyBlockMsg{
		Proposer:           block.Author,
		Epoch:              int64(block.Round),
		Payloads:           block.PayLoads,
		ConsensusBlockHash: block.Hash(),
		Sender:             make(chan mempool.VerifyStatus),
	}
	corer.connectChannel <- msg
	status := <-msg.Sender
	return status
}

func (corer *Core) handleRequestBlock(request *RequestBlockMsg) error {
	logger.Debug.Printf("procesing block request from node %d", request.Author)

	//Step 1: verify signature
	if !request.Verify(corer.committee) {
		return ErrSignature(request.MsgType(), -1, int(request.Author))
	}

	go corer.retriever.processRequest(request)

	return nil
}

func (corer *Core) handleReplyBlock(reply *ReplyBlockMsg) error {
	logger.Debug.Println("procesing block reply")

	//Step 1: verify signature
	if !reply.Verify(corer.committee) {
		return ErrSignature(reply.MsgType(), -1, int(reply.Author))
	}

	for _, block := range reply.Blocks {

		//maybe execute more one
		storeBlock(corer.store, block)

		corer.handleOutPut(block.Round, block.Author, block.Hash(), block.Reference)

		// status := corer.checkPayloads(block)
		// if status != mempool.OK {
		// 	continue
		// }
	}

	go corer.retriever.processReply(reply)

	return nil
}

func (corer *Core) handleLoopBack(block *Block) error {
	logger.Debug.Printf("procesing block loop back round %d node %d \n", block.Round, block.Author)
	status := corer.checkPayloads(block)
	if status != mempool.OK {
		return ErrLossPayloads(block.Round, int(block.Author))
	}
	err := corer.handleOutPut(block.Round, block.Author, block.Hash(), block.Reference)
	if err == nil {
		corer.loopDigests <- block.Hash()
		logger.Warn.Printf("loopback round-%d-node-%d  \n", block.Round, block.Author)
	}
	return nil
}

// mempool
func (corer *Core) handleMLoopBack(digest crypto.Digest) error {
	corer.notifyPLoad <- digest

	//re output
	block, _ := getBlock(corer.store, digest)

	if block == nil {
		logger.Debug.Printf("block is nil \n")
		return nil
	}

	if ok, _, _ := corer.checkReference(block); ok {
		err := corer.handleOutPut(block.Round, block.Author, block.Hash(), block.Reference)
		if err == nil {
			corer.loopDigests <- block.Hash()
			logger.Warn.Printf("mloopback round-%d-node-%d  \n", block.Round, block.Author)
		}
		return err
	}

	return nil
}

func (corer *Core) handleOutPut(round int, node core.NodeID, digest crypto.Digest, references map[crypto.Digest]core.NodeID) error {
	logger.Debug.Printf("procesing output round %d node %d \n", round, node)

	//receive block
	corer.localDAG.ReceiveBlock(round, node, digest, references)
	// try judge
	corer.commitor.NotifyToJudge()
	if n := corer.localDAG.GetRoundReceivedBlockNums(round); n >= corer.committee.HightThreshold() {

		return corer.advancedround(round + 1)
	}

	// if n := corer.localDAG.GetRoundReceivedBlockNums(round); n == corer.committee.HightThreshold() {
	// 	//timeout
	// 	time.AfterFunc(time.Duration(corer.parameters.DelayProposal)*time.Millisecond, func() {
	// 		corer.delayRoundCh <- round + 1
	// 	})
	// 	return nil
	// } else if n == corer.committee.Size() {
	// 	return corer.advancedround(round + 1)
	// }

	return nil
}

func (corer *Core) advancedround(round int) error {
	logger.Debug.Printf("procesing advance round %d \n", round)

	if block := corer.generatorBlock(round); block != nil {
		if propose, err := NewProposeMsg(corer.nodeID, round, block, corer.sigService); err != nil {
			return err
		} else {
			// time.AfterFunc(time.Duration(corer.parameters.NetwrokDelay)*time.Millisecond, func() {
			// 	corer.transmitor.Send(corer.nodeID, core.NONE, propose)
			// 	corer.transmitor.RecvChannel() <- propose
			// })
			corer.transmitor.Send(corer.nodeID, core.NONE, propose)
			corer.transmitor.RecvChannel() <- propose
		}
	}

	return nil
}

func (corer *Core) Run() {
	if corer.nodeID >= core.NodeID(corer.parameters.Faults) {
		//启动mempool
		go corer.MemPool.Run()
		//first propose
		block := corer.generatorBlock(0)
		if propose, err := NewProposeMsg(corer.nodeID, 0, block, corer.sigService); err != nil {
			logger.Error.Println(err)
			panic(err)
		} else {
			corer.transmitor.Send(corer.nodeID, core.NONE, propose)
			corer.transmitor.RecvChannel() <- propose
		}

		for {
			var err error
			select {
			case msg := <-corer.transmitor.RecvChannel():
				{
					switch msg.MsgType() {

					case ProposeMsgType:
						err = corer.handlePropose(msg.(*ProposeMsg))
					case RequestBlockType:
						err = corer.handleRequestBlock(msg.(*RequestBlockMsg))
					case ReplyBlockType:
						err = corer.handleReplyBlock(msg.(*ReplyBlockMsg))
					}

				}
			case round := <-corer.delayRoundCh:
				{
					err = corer.advancedround(round)
				}
			case block := <-corer.loopBackChannel:
				{
					err = corer.handleLoopBack(block)
				}
			case mblock := <-corer.mempoolbackchannel:
				{
					logger.Debug.Printf("mempoolbackchannel receive \n")
					err = corer.handleMLoopBack(mblock)
				}

			}

			if err != nil {
				logger.Warn.Println(err)
			}

		}
	}
}
