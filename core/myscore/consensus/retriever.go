package consensus

import (
	"WuKong/core"
	"WuKong/crypto"
	"WuKong/logger"
	"WuKong/store"
	"time"
)

const (
	ReqType = iota
	ReplyType
)

type reqRetrieve struct {
	typ       int
	reqID     int
	digest    []crypto.Digest
	localMiss []crypto.Digest
	nodeID    core.NodeID
	backBlock crypto.Digest
}

type Retriever struct {
	nodeID           core.NodeID
	transmitor       *core.Transmitor
	cnt              int
	pendding         map[crypto.Digest]struct{} //dealing request
	requests         map[int]*RequestBlockMsg   //Request
	loopBackBlocks   map[int]crypto.Digest      // loopback deal block
	loopBackCnts     map[int]int
	loopBackLocalCnt map[int]int
	miss2Blocks      map[crypto.Digest][]int //blocks map to reqid
	miss2LocalBlocks map[crypto.Digest][]int
	reqChannel       chan *reqRetrieve
	loopDigests      chan crypto.Digest
	sigService       *crypto.SigService
	store            *store.Store
	parameters       core.Parameters
	loopBackChannel  chan<- *Block
	localDAG         *LocalDAG
}

func NewRetriever(
	nodeID core.NodeID,
	store *store.Store,
	transmitor *core.Transmitor,
	sigService *crypto.SigService,
	parameters core.Parameters,
	loopBackChannel chan<- *Block,
	loopDigests chan crypto.Digest,
	localDAG *LocalDAG,
) *Retriever {

	r := &Retriever{
		nodeID:           nodeID,
		cnt:              0,
		pendding:         make(map[crypto.Digest]struct{}),
		requests:         make(map[int]*RequestBlockMsg),
		loopBackBlocks:   make(map[int]crypto.Digest),
		loopBackCnts:     make(map[int]int),
		reqChannel:       make(chan *reqRetrieve, 100),
		miss2Blocks:      make(map[crypto.Digest][]int),
		miss2LocalBlocks: make(map[crypto.Digest][]int),
		loopBackLocalCnt: make(map[int]int),
		localDAG:         localDAG,
		store:            store,
		sigService:       sigService,
		transmitor:       transmitor,
		parameters:       parameters,
		loopBackChannel:  loopBackChannel,
		loopDigests:      loopDigests,
	}
	go r.run()

	return r
}

func (r *Retriever) run() {
	ticker := time.NewTicker(time.Duration(r.parameters.RetryDelay))
	for {
		select {
		case req := <-r.reqChannel:
			switch req.typ {
			case ReqType: //request Block
				{
					//logger.Debug.Printf("retrieve block %x \n", req.backBlock)
					// localMiss:=req.localMiss
					// remoteMiss:=req.digest
					ok1, localMiss := r.localDAG.IsReceived(req.localMiss...)
					ok2, remoteMiss := r.localDAG.IsReceived(req.digest...)
					if ok1 && ok2 {
						go r.loopBack(req.backBlock)
						logger.Debug.Printf("one bug find \n")
						continue
					}
					r.loopBackBlocks[r.cnt] = req.backBlock
					r.loopBackCnts[r.cnt] = len(remoteMiss)
					r.loopBackLocalCnt[r.cnt] = len(localMiss)
					var missBlocks []crypto.Digest
					for i := 0; i < len(localMiss); i++ {
						r.miss2LocalBlocks[localMiss[i]] = append(r.miss2LocalBlocks[localMiss[i]], r.cnt)
					}
					for i := 0; i < len(remoteMiss); i++ { //filter block that dealing
						r.miss2Blocks[remoteMiss[i]] = append(r.miss2Blocks[remoteMiss[i]], r.cnt)
						if _, ok := r.pendding[remoteMiss[i]]; ok {
							continue
						}
						missBlocks = append(missBlocks, remoteMiss[i])
						r.pendding[remoteMiss[i]] = struct{}{}
					}

					if len(missBlocks) > 0 {
						request, _ := NewRequestBlock(r.nodeID, missBlocks, r.cnt, time.Now().UnixMilli(), r.sigService)
						logger.Debug.Printf("sending request for miss block reqID %d to %d\n", r.cnt, req.nodeID)
						_ = r.transmitor.Send(request.Author, req.nodeID, request)
						r.requests[request.ReqID] = request
					}

					r.cnt++
				}
			case ReplyType: //request finish
				{
					logger.Debug.Printf("receive reply for miss block reqID %d \n", req.reqID)
					if _, ok := r.requests[req.reqID]; ok {
						_req := r.requests[req.reqID]
						for _, d := range _req.MissBlock {
							for _, id := range r.miss2Blocks[d] {
								r.loopBackCnts[id]--
								if r.loopBackCnts[id] == 0 && r.loopBackLocalCnt[id] == 0 {
									go r.loopBack(r.loopBackBlocks[id])
								}

							}
							//delete(r.miss2Blocks, d)
							delete(r.pendding, d) // delete
						}
						delete(r.requests, _req.ReqID) //delete request that finished
					}
				}
			}
		case d := <-r.loopDigests:
			{
				for _, id := range r.miss2LocalBlocks[d] {
					r.loopBackLocalCnt[id]--
					if r.loopBackCnts[id] == 0 && r.loopBackLocalCnt[id] == 0 {
						go r.loopBack(r.loopBackBlocks[id])
					}
				}
				delete(r.miss2LocalBlocks, d)
				delete(r.pendding, d) // delete
			}
		case <-ticker.C: // recycle request
			{
				now := time.Now().UnixMilli()
				for _, req := range r.requests {
					if now-req.Ts >= int64(r.parameters.RetryDelay) {
						request, _ := NewRequestBlock(req.Author, req.MissBlock, req.ReqID, now, r.sigService)
						r.requests[req.ReqID] = request
						//BroadCast to all node
						r.transmitor.Send(r.nodeID, core.NONE, request)
					}
				}
			}
		}
	}
}

func (r *Retriever) requestBlocks(digest []crypto.Digest, localmiss []crypto.Digest, nodeid core.NodeID, backBlock crypto.Digest) {
	req := &reqRetrieve{
		typ:       ReqType,
		digest:    digest,
		localMiss: localmiss,
		nodeID:    nodeid,
		backBlock: backBlock,
	}
	r.reqChannel <- req
	// logger.Warn.Printf(" reqChannel <- req 长度：%d", len(r.reqChannel))
	// select {
	// case r.reqChannel <- req:
	// 	// 正常写入
	// default:
	// 	// 写不进去说明 channel 已满
	// 	logger.Error.Println("写入 reqChannel <- req 失败,r.reqChannel 已满")
	// }
}

func (r *Retriever) processRequest(request *RequestBlockMsg) {
	var blocks []*Block
	for _, missBlock := range request.MissBlock {
		if val, err := r.store.Read(missBlock[:]); err != nil {
			logger.Warn.Println(err)
		} else {
			block := &Block{}
			if err := block.Decode(val); err != nil {
				logger.Warn.Println(err)
				return
			} else {
				blocks = append(blocks, block)
			}
		}
	}
	//reply
	reply, _ := NewReplyBlockMsg(r.nodeID, blocks, request.ReqID, r.sigService)
	r.transmitor.Send(r.nodeID, request.Author, reply)
}

func (r *Retriever) processReply(reply *ReplyBlockMsg) {
	req := &reqRetrieve{
		typ:   ReplyType,
		reqID: reply.ReqID,
	}
	r.reqChannel <- req
}

// func (r *reqRetrieve) processLoopHash(loopDigest crypto.Digest) {

// }

func (r *Retriever) loopBack(blockHash crypto.Digest) {
	// logger.Debug.Printf("processing loopback")
	if val, err := r.store.Read(blockHash[:]); err != nil {
		//must be  received
		logger.Error.Println(err)
		panic(err)
	} else {
		block := &Block{}
		if err := block.Decode(val); err != nil {
			logger.Warn.Println(err)
			panic(err)
		} else {
			r.loopBackChannel <- block
		}
	}
}
