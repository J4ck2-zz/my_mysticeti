package consensus

import (
	"WuKong/core"
	"fmt"
)

var (
	ErrSignature = func(msgTyp, round, node int) error {
		return fmt.Errorf("[type-%d-round-%d-node-%d] message signature verify error", msgTyp, round, node)
	}

	ErrReference = func(msgTyp, round, node int) error {
		return fmt.Errorf("[type-%d-round-%d-node-%d] not receive all block reference ", msgTyp, round, node)
	}

	ErrLocalReference = func(msgTyp, round, node, miss, nums int) error {
		return fmt.Errorf("[type-%d-round-%d-node-%d] %d reference not receive,%d reference receive but not write to DAG ", msgTyp, round, node, miss, nums)
	}

	ErrLossPayloads = func(round, node int) error {
		return fmt.Errorf("[round-%d-node-%d] not receive all payloads ", round, node)
	}

	ErrUsedElect = func(msgTyp, round, node int) error {
		return fmt.Errorf("[type-%d-round-%d-node-%d] receive one more elect msg from %d ", msgTyp, round, node, node)
	}

	ErrOneMoreMessageCoin = func(msgTyp, round int, slot, author core.NodeID) error {
		return fmt.Errorf("[type-%d-epoch-%d-round-%d] receive one more message from %d ", msgTyp, round, slot, author)
	}

	ErrOneMoreMessage = func(msgTyp int, epoch, round int64, author core.NodeID) error {
		return fmt.Errorf("[type-%d-epoch-%d-round-%d] receive one more message from %d ", msgTyp, epoch, round, author)
	}

	ErrFullMemory = func(author core.NodeID) error {
		return fmt.Errorf("author %d Mempool memory is full", author)
	}

	ErrLosssMVBAValue = func() error {
		return fmt.Errorf("loss sMVBA Value")
	}
)
