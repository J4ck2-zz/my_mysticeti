package mempool

import (
	"WuKong/core"
	"WuKong/logger"
	"WuKong/network"
)

type Transmit struct {
	sender     *network.Sender
	receiver   *network.Receiver
	mempoolCh  chan core.Message //consensus通信通道
	msgCh      chan *network.NetMessage
	parameters core.Parameters
	committee  core.Committee
}

func NewTransmit(
	sender *network.Sender,
	receiver *network.Receiver,
	parameters core.Parameters,
	committee core.Committee,
) *Transmit {

	tr := &Transmit{
		sender:     sender,
		receiver:   receiver,
		mempoolCh:  make(chan core.Message, 10_000),
		msgCh:      make(chan *network.NetMessage, 10_000),
		parameters: parameters,
		committee:  committee,
	}

	go func() {
		for msg := range tr.msgCh {
			tr.sender.Send(msg)
		}
	}()

	go func() {
		for msg := range tr.receiver.RecvChannel() {
			switch msg.Module() {
			case "mempool":
				tr.mempoolCh <- msg
			default:
				logger.Warn.Printf("Unknown module %s", msg.Module())
			}
		}
	}()

	return tr
}

func (tr *Transmit) MempoolSend(from, to core.NodeID, msg core.Message) error {
	var addr []string

	if to == core.NONE {
		addr = tr.committee.MempoolBroadCast(from)
	} else {
		addr = append(addr, tr.committee.MempoolAddress(to))
	}

	tr.msgCh <- &network.NetMessage{
		Msg:     msg,
		Address: addr,
	}
	return nil
}

func (tr *Transmit) MempoolRecv() core.Message {
	return <-tr.mempoolCh
}

func (tr *Transmit) MempoolChannel() chan core.Message { //共识部分的通道
	return tr.mempoolCh
}