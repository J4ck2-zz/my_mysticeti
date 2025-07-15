package mempool

import (
	"WuKong/core"
	"WuKong/crypto"
	"WuKong/logger"
	"WuKong/store"
	"time"
)

type Synchronizer struct {
	Name         core.NodeID
	Store        *store.Store
	Transimtor   *Transmit
	LoopBackChan chan crypto.Digest
	Parameters   core.Parameters
	//consensusCoreChan chan<- core.Messgae //只接收消息
	interChan chan core.Message
}

func NewSynchronizer(
	Name core.NodeID,
	Transimtor *Transmit,
	LoopBackChan chan crypto.Digest,
	//consensusCoreChan chan<- core.Messgae,
	parameters core.Parameters,
	store *store.Store,
) *Synchronizer {
	return &Synchronizer{
		Name:         Name,
		Store:        store,
		Transimtor:   Transimtor,
		LoopBackChan: LoopBackChan,
		Parameters:   parameters,
		//consensusCoreChan: consensusCoreChan,
		interChan: make(chan core.Message, 1000),
	}
}

func (sync *Synchronizer) Cleanup(epoch uint64) {
	message := &SyncCleanUpBlockMsg{
		epoch,
	}
	sync.interChan <- message
}

func (sync *Synchronizer) Verify(proposer core.NodeID, Epoch int64, digests []crypto.Digest, consensusblockhash crypto.Digest) VerifyStatus {
	logger.Debug.Printf("sync *Synchronizer verify all small block\n")
	var missing []crypto.Digest
	for _, digest := range digests {
		if _, err := sync.Store.Read(digest[:]); err != nil {
			missing = append(missing, digest)
		}
	}
	if len(missing) == 0 {
		return OK
	}
	message := &SyncBlockMsg{
		missing, proposer, Epoch, consensusblockhash,
	}
	sync.interChan <- message

	logger.Debug.Printf("round %d node %d miss payloads len=%d \n", Epoch, proposer, len(missing))
	return Wait
}

func (sync *Synchronizer) VerifyAgain(to core.NodeID, requestmsg *RequestPayloadMsg) {
	logger.Debug.Printf("verify again request payload msg\n")
	var missing []crypto.Digest
	for _, digest := range requestmsg.Digests {
		if _, err := sync.Store.Read(digest[:]); err != nil {
			missing = append(missing, digest)
		}
	}
	if len(missing) == 0 {
		return
	}
	requestmsg.Digests = missing
	sync.Transimtor.MempoolSend(sync.Name, to, requestmsg)
	logger.Debug.Printf("send payload request reqid %d to %d \n", requestmsg.ReqId, to)

}

func (sync *Synchronizer) Run() {
	ticker := time.NewTicker(time.Duration(sync.Parameters.RetryDelay) * time.Millisecond) //定时进行请求区块
	defer ticker.Stop()
	pending := make(map[crypto.Digest]struct {
		Epoch   uint64
		Notify  chan<- struct{}
		Missing []crypto.Digest
		Author  core.NodeID
		Ts      int64
	})
	waiting := make(chan crypto.Digest, 10_000)
	var reqid int = 0
	for {
		select {
		case reqMsg := <-sync.interChan:
			{
				switch reqMsg.MsgType() {
				case SyncBlockType:
					req, _ := reqMsg.(*SyncBlockMsg)
					digest := req.ConsensusBlockHash
					if _, ok := pending[digest]; ok {
						continue
					}
					notify := make(chan struct{})
					go func() {
						waiting <- waiter(req.Missing, req.ConsensusBlockHash, *sync.Store, notify)
					}()
					pending[digest] = struct {
						Epoch   uint64
						Notify  chan<- struct{}
						Missing []crypto.Digest
						Author  core.NodeID
						Ts      int64
					}{uint64(req.Epoch), notify, req.Missing, req.Author, time.Now().UnixMilli()}
					message := &RequestPayloadMsg{
						Digests: req.Missing,
						Author:  sync.Name,
						ReqId:   reqid,
					}
					//找作者要相关的区块
					if reqid >1000{
						time.AfterFunc(time.Duration(sync.Parameters.RequestPloadDelay*5)*time.Millisecond, func() {
							sync.VerifyAgain(req.Author, message)
						})
					}else if reqid > 500 {
						time.AfterFunc(time.Duration(sync.Parameters.RequestPloadDelay*2)*time.Millisecond, func() {
							sync.VerifyAgain(req.Author, message)
						})
					} else if reqid > 200 {
						// logger.Debug.Printf("create payload request reqid %d to %d \n", reqid, req.Author)
						time.AfterFunc(time.Duration(sync.Parameters.RequestPloadDelay)*time.Millisecond, func() {
							sync.VerifyAgain(req.Author, message)
						})
					} else {
						sync.Transimtor.MempoolSend(sync.Name, req.Author, message)
						logger.Debug.Printf("send payload request reqid %d to %d \n", reqid, req.Author)
					}
					reqid++
					//找所有人要
					//sync.Transimtor.Send(sync.Name, core.NONE, message)
				case SyncCleanUpBlockType:
					req, _ := reqMsg.(*SyncCleanUpBlockMsg)
					var keys []crypto.Digest
					for key, val := range pending {
						if val.Epoch <= req.Epoch {
							close(val.Notify)
							keys = append(keys, key)
						}
					}
					for _, key := range keys {
						delete(pending, key)
					}
				}
			}
		case block := <-waiting:
			{
				if block != (crypto.Digest{}) {
					//logger.Error.Printf("successfully get the ask block\n")
					delete(pending, block)
					//LoopBack
					// msg := &LoopBackMsg{
					// 	BlockHash: block,
					// }
					sync.LoopBackChan <- block
					//sync.Transimtor.RecvChannel() <- msg
				}
			}
		case <-ticker.C:
			{
				logger.Debug.Printf("recycle request start,length is %d\n", len(pending))
				if len(pending) < 20 {
					now := time.Now().UnixMilli()
					for digest, req := range pending {
						if now-req.Ts >= int64(sync.Parameters.RetryDelay) {
							logger.Debug.Printf("recycle request and len of pending is %d\n", len(pending))
							msg := &RequestPayloadMsg{
								Digests: req.Missing,
								Author:  sync.Name,
								ReqId:   -1,
							}
							//找所有人要
							sync.Transimtor.MempoolSend(sync.Name, core.NONE, msg)

							req.Ts = now
							pending[digest] = req
						}
					}
				}
			}

		}
	}
}

func waiter(missing []crypto.Digest, blockhash crypto.Digest, store store.Store, notify <-chan struct{}) crypto.Digest {
	finish := make(chan struct{})
	go func() {
		for _, digest := range missing {
			store.NotifyRead(digest[:])
		}
		close(finish)
	}()

	select {
	case <-finish:
	case <-notify:
		return crypto.Digest{}
	}
	return blockhash
}
