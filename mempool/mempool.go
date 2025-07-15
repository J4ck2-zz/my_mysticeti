package mempool

import (
	"WuKong/core"
	"WuKong/crypto"
	"WuKong/logger"
	"WuKong/network"
	"WuKong/pool"
	"WuKong/store"
	"fmt"

	//"log"
	"net"
	"strings"
	"sync"
	"time"
)

type Mempool struct {
	Name           core.NodeID
	Committee      core.Committee
	Parameters     core.Parameters
	SigService     *crypto.SigService
	Store          *store.Store
	TxPool         *pool.Pool
	Transimtor     *Transmit
	muSelfQueue    *sync.RWMutex
	SelfQueue      map[crypto.Digest]struct{}
	Queue          map[crypto.Digest]struct{} //整个mempool的最大容量
	Sync           *Synchronizer
	connectChannel chan core.Message
	//ConsensusMempoolCoreChan <-chan core.Messgae
}

func NewMempool(
	Name core.NodeID,
	Committee core.Committee,
	Parameters core.Parameters,
	SigService *crypto.SigService,
	Store *store.Store,
	TxPool *pool.Pool,
	mempoolbackchannel chan crypto.Digest,
	connectChannel chan core.Message,
	//consensusMempoolCoreChan <-chan core.Messgae,
) *Mempool {
	m := &Mempool{
		Name:           Name,
		Committee:      Committee,
		Parameters:     Parameters,
		SigService:     SigService,
		Store:          Store,
		TxPool:         TxPool,
		connectChannel: connectChannel,
		muSelfQueue:    &sync.RWMutex{},
		SelfQueue:      make(map[crypto.Digest]struct{}),
		Queue:          make(map[crypto.Digest]struct{}),
		//ConsensusMempoolCoreChan: consensusMempoolCoreChan,
	}
	transmitor := initmempooltransmit(Name, Committee, Parameters)
	m.Transimtor = transmitor
	m.Sync = NewSynchronizer(Name, transmitor, mempoolbackchannel, Parameters, Store)
	return m
}

func initmempooltransmit(id core.NodeID, committee core.Committee, parameters core.Parameters) *Transmit {
	//step1 .Invoke networl
	// parts := strings.Split(committee.MempoolAddress(id), ":")
	// if len(parts) < 2 {
	// 	log.Panicf("invalid mempool address: %s", committee.MempoolAddress(id))
	// }
	// addr := fmt.Sprintf(":%s", parts[1])
	addr := fmt.Sprintf(":%s", strings.Split(committee.MempoolAddress(id), ":")[1])
	cc := network.NewCodec(DefaultMessageTypeMap)
	sender := network.NewSender(cc)
	go sender.Run()
	receiver := network.NewReceiver(addr, cc)
	go receiver.Run()
	transimtor := NewTransmit(sender, receiver, parameters, committee)

	//Step 2: Waiting for all nodes to be online
	logger.Info.Println("Waiting for all mempool nodes to be online...")
	time.Sleep(time.Millisecond * time.Duration(parameters.SyncTimeout))
	addrs := committee.MempoolBroadCast(id)
	wg := sync.WaitGroup{}
	for _, addr := range addrs {
		wg.Add(1)
		go func(address string) {
			defer wg.Done()
			for {
				conn, err := net.Dial("tcp", address)
				if err != nil {
					time.Sleep(time.Microsecond * 200)
					continue
				}
				conn.Close()
				break
			}
		}(addr)
	}
	wg.Wait()

	return transimtor
}

func (c *Mempool) StorePayload(payload *Payload) error {
	key := payload.Hash()
	value, err := payload.Encode()
	if err != nil {
		return err
	}
	return c.Store.Write(key[:], value)
}

func (c *Mempool) GetPayload(digest crypto.Digest) (*Payload, error) {
	value, err := c.Store.Read(digest[:])

	if err == store.ErrNotFoundKey {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	b := &Payload{}
	if err := b.Decode(value); err != nil {
		return nil, err
	}
	return b, err
}

func ErrFullMemory(author core.NodeID) error {
	return fmt.Errorf("author %d Mempool memory is full", author)
}

func (m *Mempool) payloadProcess(payload *Payload) error {

	if uint64(len(m.Queue)) >= m.Parameters.MaxMempoolQueenSize {
		return ErrFullMemory(m.Name)
	}
	//本地存储
	if err := m.StorePayload(payload); err != nil {
		return err
	}
	//转发给其他人
	message := &OtherPayloadMsg{
		Payload: payload,
	}
	m.Transimtor.MempoolSend(m.Name, core.NONE, message)
	return nil
}

func (m *Mempool) HandleOwnPayload(payload *OwnPayloadMsg) error {
	//logger.Debug.Printf("handle mempool OwnBlockMsg\n")  自己的值先不加入自己的内存池队列，给一个缓冲的时间，尽量减少去要payload的时间
	if uint64(len(m.Queue)+len(m.SelfQueue)) >= m.Parameters.MaxMempoolQueenSize {
		return ErrFullMemory(m.Name)
	}
	digest := payload.Payload.Hash()
	if err := m.payloadProcess(payload.Payload); err != nil {
		return err
	}
	time.AfterFunc(time.Duration(m.Parameters.PayloadDelay)*time.Millisecond, func() {
		m.muSelfQueue.Lock()
		m.SelfQueue[digest] = struct{}{}
		m.muSelfQueue.Unlock()
	})

	return nil
}

func (m *Mempool) HandleOthorPayload(payload *OtherPayloadMsg) error {
	//m.generateBlocks()
	//logger.Debug.Printf("handle mempool otherBlockMsg\n")
	if uint64(len(m.Queue)+len(m.SelfQueue)) >= m.Parameters.MaxMempoolQueenSize {
		return ErrFullMemory(m.Name)
	}

	digest := payload.Payload.Hash()
	// Verify that the payload is correctly signed.
	if flag := payload.Payload.Verify(m.Committee); !flag {
		logger.Error.Printf("Block sign error\n")
		return nil
	}
	if err := m.StorePayload(payload.Payload); err != nil {
		return err
	}
	logger.Info.Printf("receive batch %d from %d\n", payload.Payload.Batch.ID, payload.Payload.Proposer)
	m.Queue[digest] = struct{}{}
	return nil
}

func (m *Mempool) HandleRequestPayload(request *RequestPayloadMsg) error {
	logger.Debug.Printf("handle mempool RequestBlockMsg reqid %d from %d\n", request.ReqId, request.Author)
	var payloads []*Payload
	for _, digest := range request.Digests {
		if p, err := m.GetPayload(digest); err != nil {
			logger.Warn.Println(err)
		} else {
			payloads = append(payloads, p)
			logger.Debug.Printf("miss payload id %d proposer %d\n", p.Batch.ID, p.Proposer)
		}
	}
	// 分批发送，每次最多 5 个
	const batchSize = 5
	total := len(payloads)
	for i := 0; i < total; i += batchSize {
		end := min(i+batchSize, total)

		message := &ReplyPayloadRequestMsg{
			Payload: payloads[i:end],
			Author:  m.Name,
		}
		m.Transimtor.MempoolSend(m.Name, request.Author, message)
	}
	return nil
}

// 获取共识区块所引用的微区块
func (m *Mempool) HandleMakeBlockMsg(makemsg *MakeConsensusBlockMsg) ([]crypto.Digest, error) {
	//nums := makemsg.MaxBlockSize / uint64(len(crypto.Digest{}))
	nums := m.Parameters.MaxPayloadNum
	ret := make([]crypto.Digest, 0)
	if len(m.Queue) == 0 && len(m.SelfQueue) == 0 {
		logger.Debug.Printf("HandleMakeBlockMsg len(m.Queue) %d and len(selfqueue) %d\n", len(m.Queue), len(m.SelfQueue))
		payload, _ := NewPload(m.Name, m.TxPool.GetBatch(), m.SigService)
		if payload.Batch.ID != -1 {
			logger.Info.Printf("create payload node %d batch_id %d \n", payload.Proposer, payload.Batch.ID)
		}
		digest := payload.Hash()
		if err := m.payloadProcess(payload); err != nil {
			return nil, err
		}
		ret = append(ret, digest)
	} else {
		logger.Debug.Printf("HandleMakeBlockMsg len(m.Queue) %d and len(selfqueue) %d\n", len(m.Queue), len(m.SelfQueue))
		m.muSelfQueue.Lock()
		for key := range m.SelfQueue {
			ret = append(ret, key)
			delete(m.SelfQueue, key)
			nums--
			if nums == 0 {
				break
			}
		}
		m.muSelfQueue.Unlock()
		if nums > 0 {
			for key := range m.Queue {
				ret = append(ret, key)
				delete(m.Queue, key)
				nums--
				if nums == 0 {
					break
				}
			}
		}
	}
	return ret, nil
}

func (m *Mempool) handleReplyPayloadMsg(msg *ReplyPayloadRequestMsg) error {
	if uint64(len(m.Queue)+len(m.SelfQueue)) >= m.Parameters.MaxMempoolQueenSize {
		return ErrFullMemory(m.Name)
	}
	for _, payload := range msg.Payload {
		if err := m.StorePayload(payload); err != nil {
			return err
		}
		m.Queue[payload.Hash()] = struct{}{}
		logger.Info.Printf("receive batch %d author%d from %d\n", payload.Batch.ID, payload.Proposer, msg.Author)
	}
	return nil
}

func (m *Mempool) HandleCleanPayload(msg *CleanBlockMsg) error {
	//本地清理删除payload
	for _, digest := range msg.Digests {
		delete(m.Queue, digest)
	}
	return nil
}

func (m *Mempool) HandleVerifyMsg(msg *VerifyBlockMsg) VerifyStatus {
	return m.Sync.Verify(msg.Proposer, msg.Epoch, msg.Payloads, msg.ConsensusBlockHash)
}

// func (m *Mempool) generatePayload() error {
// 	payload, _ := NewPload(m.Name, m.TxPool.GetBatch(), m.SigService)
// 	if payload.Batch.ID != -1 {
// 		logger.Info.Printf("create payload node %d batch_id %d \n", payload.Proposer, payload.Batch.ID)
// 		ownmessage := &OwnPayloadMsg{
// 			Payload: payload,
// 		}
// 		m.Transimtor.MempoolChannel() <- ownmessage
// 	}

// 	return nil
// }

func (m *Mempool) generatePayload() {
	batchChannal := m.TxPool.BatchChannel()
	for batch := range batchChannal {
		payload, _ := NewPload(m.Name, batch, m.SigService)
		if payload.Batch.ID != -1 {
			logger.Info.Printf("create Block node %d batch_id %d \n", payload.Proposer, payload.Batch.ID)
			ownmessage := &OwnPayloadMsg{
				Payload: payload,
			}
			m.Transimtor.MempoolChannel() <- ownmessage
		}
		if m.TxPool.Parameters.Rate > 9000 {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

const WorkerCount = 4

// func (m *Mempool) StartRequestPayloadWorkers() {
//     for i := 0; i < WorkerCount; i++ {
//         go func(id int) {
//             for msg := range m.requestPayloadChan {
//                 logger.Debug.Printf("[Worker %d] Handling request from %v", id, msg.SenderID)
//                 if err := m.HandleRequestPayload(msg); err != nil {
//                     logger.Warn.Printf("[Worker %d] Error: %v", id, err)
//                 }
//             }
//         }(i)
//     }
// }

func (m *Mempool) Run() {
	//一直广播微区块,这个时间设置需要和发块速率结合起来看，也就是rust版本里面实现的一收到一个batch就立马广播并且发块
	if m.Name < core.NodeID(m.Parameters.Faults) {
		logger.Debug.Printf("Node %d is faulty\n", m.Name)
		return
	}
	go m.generatePayload()

	go m.Sync.Run()

	//监听mempool的消息通道

	mempoolrecvChannal := m.Transimtor.MempoolChannel()
	connectrecvChannal := m.connectChannel
	for {
		var err error
		select {
		case msg := <-connectrecvChannal:
			{
				switch msg.MsgType() {
				case MakeBlockType:
					{
						req, _ := msg.(*MakeConsensusBlockMsg)
						data, errors := m.HandleMakeBlockMsg(req)
						req.Payloads <- data //把引用传进去了，具体使用的时候要注意,这一步要传递到哪里去？
						err = errors
					}
				case VerifyBlockType:
					{
						req, _ := msg.(*VerifyBlockMsg)
						req.Sender <- m.HandleVerifyMsg(req)
					}
				case CleanBlockType:
					{
						err = m.HandleCleanPayload(msg.(*CleanBlockMsg))
					}
				}
			}
		case msg := <-mempoolrecvChannal:
			{
				switch msg.MsgType() {
				case RequestPayloadType:
					{
						err = m.HandleRequestPayload(msg.(*RequestPayloadMsg))
					}
				case OtherPayloadType:
					{
						err = m.HandleOthorPayload(msg.(*OtherPayloadMsg))
					}
				case OwnPayloadType:
					{
						err = m.HandleOwnPayload(msg.(*OwnPayloadMsg))
					}
				case ReplyPayloadRequestType:
					{
						err = m.handleReplyPayloadMsg(msg.(*ReplyPayloadRequestMsg))
					}

				}
			}
		default:
		}
		if err != nil {
			switch err.(type) {
			default:
				logger.Error.Printf("Mempool Core: %s\n", err.Error())
			}
		}
	}
}
