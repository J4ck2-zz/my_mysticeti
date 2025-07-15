package consensus

import (
	"WuKong/core"
	"WuKong/crypto"
	"WuKong/logger"
	"WuKong/mempool"
	"WuKong/network"
	"WuKong/pool"
	"WuKong/store"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func Consensus(
	id core.NodeID,
	committee core.Committee,
	parameters core.Parameters,
	txpool *pool.Pool,
	store *store.Store,
	sigService *crypto.SigService,

	mempoolbackchannel chan crypto.Digest,
	connectChannel chan core.Message,
	commitChannel chan<- *Block,
	mempool *mempool.Mempool,
) error {
	logger.Info.Printf(
		"Consensus Node ID: %d\n",
		id,
	)
	// logger.Info.Printf(
	// 	"Consensus committee: %+v\n",
	// 	committee,
	// )
	logger.Info.Printf(
		"Consensus DDos: %v, Faults: %v \n",
		parameters.DDos, parameters.Faults,
	)
	if id < core.NodeID(parameters.Faults) {
		logger.Info.Println("Byzantine Node")
	} else {
		logger.Info.Println("Honest Node")
	}

	//Step 1: invoke network
	cc := network.NewCodec(DefaultMsgTypes)
	addr := fmt.Sprintf(":%s", strings.Split(committee.Address(id), ":")[1])
	sender, receiver := network.NewSender(cc), network.NewReceiver(addr, cc)
	//
	go sender.Run()
	go receiver.Run()
	transmitor := core.NewTransmitor(sender, receiver, parameters, committee)

	//Step 2: Waiting for all nodes to be online
	logger.Info.Println("Waiting for all nodes to be online...")
	wg := sync.WaitGroup{}
	addrs := committee.BroadCast(id)
	for _, addr := range addrs {
		wg.Add(1)
		go func(address string) {
			defer wg.Done()
			for {
				conn, err := net.Dial("tcp", address)
				if err != nil {
					time.Sleep(time.Millisecond * 10)
					continue
				}
				conn.Close()
				return
			}
		}(addr)
	}
	wg.Wait()
	time.Sleep(time.Millisecond * time.Duration(parameters.SyncTimeout))
	txpool.Run()
	//Step 3: start protocol
	corer := NewCore(id, committee, parameters, txpool, transmitor, store, sigService, commitChannel, mempoolbackchannel, connectChannel, mempool)

	go corer.Run()

	return nil
}
