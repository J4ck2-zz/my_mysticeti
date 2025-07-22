package consensus

import (
	"WuKong/core"
	"WuKong/crypto"
	"WuKong/logger"
	"WuKong/mempool"
	"WuKong/store"
	"sync"
)

type pattern int

const (
	unjudge pattern = iota
	toskip
	undecide
	toCommit
	mvbaing
)

type LocalDAG struct {
	store        *store.Store
	committee    core.Committee
	muBlock      *sync.RWMutex
	blockDigests map[crypto.Digest]core.NodeID // store hash of block that has received
	muDAG        *sync.RWMutex
	localDAG     map[int]map[core.NodeID][]crypto.Digest // local DAG
	edgesDAG     map[int]map[core.NodeID][]map[crypto.Digest]core.NodeID
	muCert       *sync.RWMutex
	iscertDAG    map[int]map[core.NodeID]pattern //proposer pattern
	muAnchor     *sync.RWMutex
	anchors      map[int]struct{}
}

func NewLocalDAG(store *store.Store, committee core.Committee) *LocalDAG {
	return &LocalDAG{
		muBlock:      &sync.RWMutex{},
		muDAG:        &sync.RWMutex{},
		muCert:       &sync.RWMutex{},
		muAnchor:     &sync.RWMutex{},
		blockDigests: make(map[crypto.Digest]core.NodeID),
		localDAG:     make(map[int]map[core.NodeID][]crypto.Digest),
		edgesDAG:     make(map[int]map[core.NodeID][]map[crypto.Digest]core.NodeID),
		iscertDAG:    make(map[int]map[core.NodeID]pattern),
		anchors:      make(map[int]struct{}),
		store:        store,
		committee:    committee,
	}
}

// IsReceived: digests is received ?
func (local *LocalDAG) IsReceived(digests ...crypto.Digest) (bool, []crypto.Digest) {
	local.muBlock.RLock()
	defer local.muBlock.RUnlock()

	var miss []crypto.Digest
	var flag bool = true
	for _, d := range digests {
		if _, ok := local.blockDigests[d]; !ok {
			miss = append(miss, d)
			flag = false
		}
	}

	return flag, miss
}

func (local *LocalDAG) ReceiveBlock(round int, node core.NodeID, digest crypto.Digest, references map[crypto.Digest]core.NodeID) {
	local.muBlock.RLock()
	if _, ok := local.blockDigests[digest]; ok {
		local.muBlock.RUnlock()
		return
	}
	local.muBlock.RUnlock()

	logger.Debug.Printf("ReceiveBlock: round=%d node=%d ", round, node)
	local.muBlock.Lock()
	local.blockDigests[digest] = node
	local.muBlock.Unlock()

	local.muCert.Lock()
	certslot, ok := local.iscertDAG[round]
	if !ok {
		certslot = make(map[core.NodeID]pattern)
		local.iscertDAG[round] = certslot
	}
	_, ok = local.iscertDAG[round][node]
	if !ok {
		certslot[node] = unjudge
	}
	local.muCert.Unlock()

	local.muDAG.Lock()
	vslot, ok := local.localDAG[round]
	if !ok {
		vslot = make(map[core.NodeID][]crypto.Digest)
		local.localDAG[round] = vslot
	}

	eslot, ok := local.edgesDAG[round]
	if !ok {
		eslot = make(map[core.NodeID][]map[crypto.Digest]core.NodeID)
		local.edgesDAG[round] = eslot
	}

	vslot[node] = append(vslot[node], digest)
	eslot[node] = append(eslot[node], references)
	local.muDAG.Unlock()
}

func (local *LocalDAG) GetRoundReceivedBlockNums(round int) (nums int) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()

	nums = len(local.localDAG[round])

	return
}

func (local *LocalDAG) GetReceivedBlock(round int, node core.NodeID) ([]crypto.Digest, bool) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	if slot, ok := local.localDAG[round]; ok {
		d, ok := slot[node]
		return d, ok
	}
	return nil, false
}

func (local *LocalDAG) GetReceivedBlockReference(round int, node core.NodeID) (map[crypto.Digest]core.NodeID, bool) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()
	if slot, ok := local.edgesDAG[round]; ok {
		reference, ok := slot[node]
		if ok {
			return reference[0], ok
		}
	}
	return nil, false
}

func (local *LocalDAG) GetRoundReceivedBlock(round int) map[core.NodeID][]crypto.Digest {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()

	original := local.localDAG[round]

	copied := make(map[core.NodeID][]crypto.Digest, len(original))
	for k, v := range original {
		tmp := make([]crypto.Digest, len(v))
		copy(tmp, v)
		copied[k] = tmp
	}

	return copied
}

func (local *LocalDAG) GetRoundReceivedBlocks(round int) (references map[crypto.Digest]core.NodeID) {
	local.muDAG.RLock()
	defer local.muDAG.RUnlock()

	blocks := local.localDAG[round]

	references = make(map[crypto.Digest]core.NodeID)
	for id, digests := range blocks {
		references[digests[0]] = id
	}
	return references
}

// judge if bvote refer to bproposer
func (local *LocalDAG) isVote(Bproposer *Block, Bvote *Block) bool {
	id := Bproposer.Author
	r := Bproposer.Round

	return local.supportedblock(Bvote, id, r) == Bproposer.Hash()

}

func (local *LocalDAG) supportedblock(b *Block, id core.NodeID, r int) crypto.Digest {

	digests := b.Reference

	if r >= b.Round {
		return crypto.Digest{}
	}
	for key, value := range digests {
		if value == id && r == b.Round-1 {
			return key
		}

	}
	return crypto.Digest{}
}

func (local *LocalDAG) isCert(Bproposer *Block, Bcert *Block) bool {
	digests := Bcert.Reference

	var voteCount int = 0
	for key := range digests {
		if bvote, err := getBlock(local.store, key); err != nil {
			logger.Warn.Println(err)
			continue
		} else {
			if local.isVote(Bproposer, bvote) {
				voteCount++
			}
		}
	}

	return voteCount >= local.committee.HightThreshold()

}

func (local *LocalDAG) GetVotingBlocks(round int) map[core.NodeID][]crypto.Digest {

	return local.GetRoundReceivedBlock(round)

}

func (local *LocalDAG) GetDecisonBlocks(b *Block) map[core.NodeID][]crypto.Digest {

	return local.GetRoundReceivedBlock(b.Round + 2)

}

func (local *LocalDAG) skippedProposer(id core.NodeID, round int) bool {
	var res int = 0

	blocks := local.GetVotingBlocks(round + 1)
	for _, digests := range blocks {
		var flag bool = true
		for _, digest := range digests {
			if block, err := getBlock(local.store, digest); err != nil {
				logger.Warn.Println(err)
			} else {
				if containsValue(block.Reference, id) {
					flag = false
					break
				}
			}
		}
		if flag {
			res++
		}
	}

	return res >= local.committee.HightThreshold()
}

func containsValue(m map[crypto.Digest]core.NodeID, target core.NodeID) bool {
	for _, v := range m {
		if v == target {
			return true
		}
	}
	return false
}

func (local *LocalDAG) committedProposer(b *Block) bool {
	var certCount int = 0

	blocks := local.GetDecisonBlocks(b)
	for _, digests := range blocks {
		for _, digest := range digests {
			if block, err := getBlock(local.store, digest); err != nil {
				logger.Warn.Println(err)
				continue
			} else {
				if local.isCert(b, block) {
					certCount++
					break
				}
			}
		}
	}

	return certCount >= local.committee.HightThreshold()
}

// find a link from b to a
func (local *LocalDAG) isLink(a, b crypto.Digest, deep int) bool {
	if deep < 0 {
		return false
	}

	if a == b {
		return true
	}
	block, err := getBlock(local.store, b)
	if err != nil {
		logger.Warn.Println(err)
		logger.Debug.Printf("end  not exist")
		return false
	}
	for ref := range block.Reference {
		if local.isLink(a, ref, deep-1) {
			return true
		}
	}

	return false
}

// decide anchor
func (local *LocalDAG) isRoundAnchor(round int, node core.NodeID) bool {
	local.muAnchor.Lock()
	defer local.muAnchor.Unlock()
	_, ok := local.anchors[round]
	if ok {
		return false
	}

	if node == core.NodeID(0) {
		local.anchors[round] = struct{}{}
		logger.Debug.Printf("round %d anchor is node %d\n", round, node)
		return true
	}
	local.muCert.Lock()
	for i := 0; i < int(node); i++ {
		if local.iscertDAG[round][core.NodeID(i)] == toskip {
			continue
		}
		local.muCert.Unlock()
		return false
	}
	local.muCert.Unlock()
	local.anchors[round] = struct{}{}
	logger.Debug.Printf("round %d anchor is node %d\n", round, node)
	return true
}

// false,-1 已经确定anchor  -2 还不能选出anchor  -3 lossliveness
func (local *LocalDAG) getRoundAnchor(round int) (bool, int) {
	local.muAnchor.Lock()
	defer local.muAnchor.Unlock()
	_, ok := local.anchors[round]
	if ok {
		return false, -1
	}
	local.muCert.Lock()
	for i := 0; i < local.committee.Size(); i++ {
		pter := local.iscertDAG[round][core.NodeID(i)]
		if pter == toskip {
			continue
		} else if pter == toCommit {
			local.anchors[round] = struct{}{}
			local.muCert.Unlock()
			logger.Debug.Printf("round %d anchor is node %d\n", round, i)
			return true, i
		} else if pter == undecide {
			local.muCert.Unlock()
			return false, -2
		}
	}
	local.muCert.Unlock()
	return false, -3
}

type commitMsg struct {
	round  int
	node   core.NodeID
	ptern  pattern
	digest crypto.Digest
}

type Commitor struct {
	commitChannel chan<- *Block
	localDAG      *LocalDAG
	commitBlocks  map[crypto.Digest]struct{}
	notify        chan struct{}
	notifycommit  chan *commitMsg
	inner         chan crypto.Digest
	store         *store.Store

	//mempool    *mempool.Mempool
	connectChannel  chan core.Message
	pendingPayloads map[crypto.Digest]chan struct{} // digest -> waiting channel
	muPending       *sync.RWMutex
	notifyPload     chan crypto.Digest

	commitRound int
	commitNode  core.NodeID
	judinground int
	judingnode  core.NodeID
	mucDAG      *sync.RWMutex
	certDAG     map[int]map[core.NodeID]pattern
	muDAG       *sync.RWMutex
	commitDAG   map[int]map[core.NodeID]crypto.Digest

	notifyToInderictCommit chan *Block //notify to inderict commit propose,what in channel is anchor
}

func NewCommitor(localDAG *LocalDAG, store *store.Store, commitChannel chan<- *Block, mc chan core.Message, notify chan crypto.Digest) *Commitor {
	c := &Commitor{
		mucDAG:        &sync.RWMutex{},
		muDAG:         &sync.RWMutex{},
		localDAG:      localDAG,
		commitChannel: commitChannel,
		commitBlocks:  make(map[crypto.Digest]struct{}),
		notify:        make(chan struct{}, 100),
		commitDAG:     make(map[int]map[core.NodeID]crypto.Digest),
		certDAG:       make(map[int]map[core.NodeID]pattern),
		notifycommit:  make(chan *commitMsg, 1000),
		store:         store,

		commitRound: 0,
		commitNode:  1,
		judinground: 0,
		judingnode:  1,

		connectChannel: mc,
		//mempool:       mempool,
		pendingPayloads: make(map[crypto.Digest]chan struct{}),
		muPending:       &sync.RWMutex{},
		notifyPload:     notify,

		inner: make(chan crypto.Digest, 100),

		notifyToInderictCommit: make(chan *Block, 100),
	}
	go c.run()
	return c
}

func (c *Commitor) waitForPayload(digest crypto.Digest) {
	c.muPending.Lock()
	ch, ok := c.pendingPayloads[digest]
	if !ok {
		ch = make(chan struct{}, 1)
		c.pendingPayloads[digest] = ch
	}
	c.muPending.Unlock()
	// 阻塞等待直到 payload 被收到并写入此通道
	<-ch
	logger.Debug.Printf("channel receive \n")
	c.muPending.Lock()
	delete(c.pendingPayloads, digest)
	c.muPending.Unlock()

}

func (c *Commitor) run() {

	go func() {
		for digest := range c.inner {
			//logger.Debug.Printf("inner receive block digest %x\n", digest)
			if block, err := getBlock(c.store, digest); err != nil {
				logger.Warn.Println(err)
			} else {

				flag := false
				for _, d := range block.PayLoads {
					payload, err := GetPayload(c.store, d)
					if err != nil {
						logger.Debug.Printf("miss payload round %d node %d\n", block.Round, block.Author)
						//  1. 向网络请求缺失 payload

						msg := &mempool.VerifyBlockMsg{
							Proposer:           block.Author,
							Epoch:              int64(block.Round),
							Payloads:           block.PayLoads,
							ConsensusBlockHash: block.Hash(),
							Sender:             make(chan mempool.VerifyStatus),
						}

						c.connectChannel <- msg
						status := <-msg.Sender
						if status != mempool.OK {
							//  2. 等待 payload 补全（阻塞等待）

							c.waitForPayload(digest)
							logger.Debug.Printf("receive payload by verify \n")
						}
						payload, _ = GetPayload(c.store, d)
					}
					if payload.Batch.ID != -1 {
						flag = true
						logger.Info.Printf("commit batch %d \n", payload.Batch.ID)
					} else {
						logger.Debug.Printf("batch is nil \n")
					}

				}
				c.commitChannel <- block
				// if len(block.PayLoads)==1&&
				if flag {
					logger.Info.Printf("commit Block round %d node %d \n", block.Round, block.Author)
					c.connectChannel <- &mempool.CleanBlockMsg{
						Digests: block.PayLoads,
					}
				}

			}
		}
	}()
	go func() {
		for m := range c.notifyToInderictCommit {
			c.handleAnchor(m)
		}
	}()
	go func() {
		for m := range c.notifycommit {
			c.receivePattern(m)
		}
	}()
	go func() {
		for digest := range c.notifyPload {
			c.muPending.RLock()
			if ch, ok := c.pendingPayloads[digest]; ok {
				select {
				case ch <- struct{}{}: // 通知已经到达
				default: // 防止阻塞，如果已经有人写过了就跳过
				}
			}
			c.muPending.RUnlock()
		}
	}()
	for range c.notify {
		c.judgePattern()

	}
}

func (c *Commitor) judgePattern() {
	for {

		if c.localDAG.GetRoundReceivedBlockNums(c.judinground+1) >= c.localDAG.committee.HightThreshold() {
			if c.localDAG.skippedProposer(c.judingnode, c.judinground) {
				logger.Debug.Printf("judge  round %d node %d  toskip \n", c.judinground, c.judingnode)
				c.modifyCertDAG(c.judinground, c.judingnode, toskip)
				c.notifycommit <- &commitMsg{
					round:  c.judinground,
					node:   c.judingnode,
					ptern:  toskip,
					digest: crypto.Digest{},
				}
				c.advancedJudingPointer()
				continue
			} else if c.localDAG.GetRoundReceivedBlockNums(c.judinground+2) >= c.localDAG.committee.HightThreshold() {
				c.localDAG.muDAG.RLock()
				digests := c.localDAG.localDAG[c.judinground][c.judingnode]
				c.localDAG.muDAG.RUnlock()

				var ifCommit bool = false
				for _, digest := range digests {
					if block, err := getBlock(c.store, digest); err != nil {
						logger.Warn.Println(err)
					} else {
						flag := c.localDAG.committedProposer(block)
						if flag {
							c.modifyCertDAG(c.judinground, c.judingnode, toCommit)
							c.notifycommit <- &commitMsg{
								round:  c.judinground,
								node:   c.judingnode,
								ptern:  toCommit,
								digest: digest,
							}

							logger.Debug.Printf("judge  round %d node %d  tocommit \n", c.judinground, c.judingnode)
							ifCommit = true
							if c.localDAG.isRoundAnchor(c.judinground, c.judingnode) {
								c.notifyToInderictCommit <- block
							}
							c.advancedJudingPointer()
							break
						}

					}
				}

				if !ifCommit {
					c.modifyCertDAG(c.judinground, c.judingnode, undecide)
					logger.Debug.Printf("undecided round %d node %d \n", c.judinground, c.judingnode)
					c.notifycommit <- &commitMsg{
						round:  c.judinground,
						node:   c.judingnode,
						ptern:  undecide,
						digest: crypto.Digest{},
					}

					c.advancedJudingPointer()
				}
			} else { //no 2f+1 decisionblocks
				break
			}
		} else { //no 2f+1 votingblocks
			break
		}

	}

}

func (c *Commitor) modifyCertDAG(round int, node core.NodeID, pter pattern) {
	c.localDAG.muCert.Lock()
	c.localDAG.iscertDAG[round][node] = pter
	c.localDAG.muCert.Unlock()
}

func (c *Commitor) tryToCommit() {
	for {
		ptern, ok := c.certDAG[c.commitRound]

		if !ok {
			break
		} else {
			if ptern[c.commitNode] == toCommit {
				logger.Debug.Printf("commit round %d node %d \n", c.commitRound, c.commitNode)
				c.muDAG.Lock()
				digest := c.commitDAG[c.commitRound][c.commitNode]
				c.inner <- digest
				//logger.Debug.Printf("send inner block digest %x\n", digest)
				c.muDAG.Unlock()
				c.advancedCommitPointer()
			} else if ptern[c.commitNode] == toskip {
				logger.Debug.Printf("skip round %d node %d \n", c.commitRound, c.commitNode)
				c.advancedCommitPointer()
			} else if ptern[c.commitNode] == undecide {
				break
			} else if ptern[c.commitNode] == unjudge {
				break
			}
		}

	}

}

func (c *Commitor) receivePattern(m *commitMsg) {
	c.mucDAG.Lock()
	defer c.mucDAG.Unlock()
	if _, ok := c.certDAG[m.round]; !ok {
		c.certDAG[m.round] = make(map[core.NodeID]pattern)
	}
	c.certDAG[m.round][m.node] = m.ptern

	if m.ptern == toCommit {
		c.muDAG.Lock()
		if _, ok := c.commitDAG[m.round]; !ok {
			c.commitDAG[m.round] = make(map[core.NodeID]crypto.Digest)
		}
		c.commitDAG[m.round][m.node] = m.digest
		c.muDAG.Unlock()
	}

	c.tryToCommit()
}

func (c *Commitor) IsReceivePattern(round int, slot core.NodeID) pattern {
	c.mucDAG.RLock()
	defer c.mucDAG.RUnlock()
	item, ok := c.certDAG[round]
	if !ok {
		return unjudge
	}
	ptern, ok := item[slot]
	if !ok {
		return unjudge
	}
	return ptern
}

func (c *Commitor) advancedJudingPointer() {
	c.judingnode++
	if c.judingnode >= 3 {
		c.judingnode = 1
		c.judinground++
	}
}

func (c *Commitor) advancedCommitPointer() {
	c.commitNode++
	if c.commitNode >= 3 {
		c.commitNode = 1
		c.commitRound++
	}
}

func (c *Commitor) NotifyToJudge() {
	c.notify <- struct{}{}
}

func (c *Commitor) tryInderictCommit(anchor *Block, bproposer *Block) {
	logger.Debug.Printf("try inderict commit round %d node %d, anchor is round %d node %d\n", bproposer.Round, bproposer.Author, anchor.Round, anchor.Author)
	blocks := c.localDAG.GetDecisonBlocks(bproposer)
	var flag bool = false
	for _, digests := range blocks {
		for _, digest := range digests {
			if block, err := getBlock(c.localDAG.store, digest); err != nil {
				logger.Warn.Println(err)
				continue
			} else {
				deep := anchor.Round - block.Round		
				flagcert := c.localDAG.isCert(bproposer, block)		
				flaglink := c.localDAG.isLink(block.Hash(), anchor.Hash(), deep)
				if flagcert && flaglink {
					c.modifyCertDAG(bproposer.Round, bproposer.Author, toCommit)
					c.notifycommit <- &commitMsg{
						round:  bproposer.Round,
						node:   bproposer.Author,
						ptern:  toCommit,
						digest: bproposer.Hash(),
					}
					logger.Debug.Printf("inderict commit round %d node %d anchor is round %d node %d\n", bproposer.Round, bproposer.Author, anchor.Round, anchor.Author)
					flag = true
					if c.localDAG.isRoundAnchor(bproposer.Round, bproposer.Author) {
						c.notifyToInderictCommit <- bproposer
					}
					break
				}
			}
		}
		if flag {
			break
		}
	}
	if !flag {
		c.modifyCertDAG(bproposer.Round, bproposer.Author, toskip)
		c.notifycommit <- &commitMsg{
			round:  bproposer.Round,
			node:   bproposer.Author,
			ptern:  toskip,
			digest: bproposer.Hash(),
		}
		logger.Debug.Printf("inderict skip round %d node %d anchor is round %d node %d\n", bproposer.Round, bproposer.Author, anchor.Round, anchor.Author)
		ok, authority := c.localDAG.getRoundAnchor(bproposer.Round)
		if ok {
			c.muDAG.Lock()
			digest := c.commitDAG[bproposer.Round][core.NodeID(authority)]
			if anchor, err := getBlock(c.localDAG.store, digest); err != nil {
				logger.Warn.Println(err)
			} else {
				c.notifyToInderictCommit <- anchor
			}
			c.muDAG.Unlock()
		}
	}
}

func (c *Commitor) handleAnchor(anchor *Block) {
	r := anchor.Round - 3
	if r < 0 {
		return
	}
	digests := c.findRoundUndecideBlocks(r)
	if digests == nil {
		logger.Debug.Printf("round %d dont exist undecided node\n", r)
	}
	for _, digest := range digests {
		if block, err := getBlock(c.localDAG.store, digest); err != nil {
			logger.Warn.Println(err)
			continue
		} else {
			c.tryInderictCommit(anchor, block)
		}
	}

}

func (c *Commitor) findRoundUndecideBlocks(round int) []crypto.Digest {
	c.localDAG.muCert.Lock()
	defer c.localDAG.muCert.Unlock()
	var digests []crypto.Digest
	for i := 0; i < c.localDAG.committee.Size(); i++ {
		if c.localDAG.iscertDAG[round][core.NodeID(i)] == undecide {
			c.localDAG.muDAG.RLock()

			digests = append(digests, c.localDAG.localDAG[round][core.NodeID(i)]...)

			c.localDAG.muDAG.RUnlock()
		}
	}
	return digests
}
