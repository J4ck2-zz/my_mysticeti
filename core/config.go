package core

import "WuKong/crypto"

type Parameters struct {
	SyncTimeout         int    `json:"sync_timeout"`
	NetwrokDelay        int    `json:"network_delay"`
	MinBlockDelay       int    `json:"min_block_delay"`
	DDos                bool   `json:"ddos"`
	Faults              int    `json:"faults"`
	RetryDelay          int    `json:"retry_delay"`
	DelayProposal       int    `json:"deley_proposal"`
	JudgeDelay          int    `json:"judge_delay"`
	PayloadDelay        int    `json:"payload_delay_send"`
	MaxPayloadNum       int    `json:"Max_Payload_Num"`
	RequestPloadDelay   int    `json:"Requst_Pload_delay"`
	MaxMempoolQueenSize uint64 `json:"maxmempoolqueensize"`
}

var DefaultParameters = Parameters{
	SyncTimeout:         500,
	NetwrokDelay:        2_00,
	MinBlockDelay:       0,
	DDos:                false,
	Faults:              0,
	RetryDelay:          5_000,
	DelayProposal:       1_000,
	JudgeDelay:          100,
	PayloadDelay:        50,
	MaxPayloadNum:       15,
	RequestPloadDelay:   1000,
	MaxMempoolQueenSize: 10_000,
}

type NodeID int

const NONE NodeID = -1

type Authority struct {
	Name        crypto.PublickKey `json:"name"`
	Id          NodeID            `json:"node_id"`
	Addr        string            `json:"addr"`
	MempoolAddr string            `json:"mempool_addr"`
}

type Committee struct {
	Authorities map[NodeID]Authority `json:"authorities"`
}

func (c Committee) ID(name crypto.PublickKey) NodeID {
	for id, authority := range c.Authorities {
		if authority.Name.Pubkey.Equal(name.Pubkey) {
			return id
		}
	}
	return NONE
}

func (c Committee) Size() int {
	return len(c.Authorities)
}

func (c Committee) Name(id NodeID) crypto.PublickKey {
	a := c.Authorities[id]
	return a.Name
}

func (c Committee) Address(id NodeID) string {
	a := c.Authorities[id]
	return a.Addr
}

func (c Committee) BroadCast(id NodeID) []string {
	addrs := make([]string, 0)
	for nodeid, a := range c.Authorities {
		if nodeid != id {
			addrs = append(addrs, a.Addr)
		}
	}
	return addrs
}

// mempool
func (c Committee) MempoolAddress(id NodeID) string {
	a := c.Authorities[id]
	return a.MempoolAddr
}

func (c Committee) MempoolBroadCast(id NodeID) []string {
	addrs := make([]string, 0)
	for nodeid, a := range c.Authorities {
		if nodeid != id {
			addrs = append(addrs, a.MempoolAddr)
		}
	}
	return addrs
}

// HightThreshold 2f+1
func (c Committee) HightThreshold() int {
	n := len(c.Authorities)
	return 2*((n-1)/3) + 1
}

// LowThreshold f+1
func (c Committee) LowThreshold() int {
	n := len(c.Authorities)
	return (n-1)/3 + 1
}
