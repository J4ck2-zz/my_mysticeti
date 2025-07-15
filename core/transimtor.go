package core

import (
	"WuKong/logger"
	"WuKong/network"
)

type Message interface {
	MsgType() int
	Module() string // return "mempool" or "consensus" or connect

}

type Transmitor struct {
	sender   *network.Sender
	receiver *network.Receiver
	// mempoolCh  chan Message //mempool内部通道
	// connectCh  chan Message //mempool和consensus通信通道
	smvbaCh    chan Message //smvba 消息通道
	recvCh     chan Message //consensus通信通道
	msgCh      chan *network.NetMessage
	parameters Parameters
	committee  Committee
}

func NewTransmitor(
	sender *network.Sender,
	receiver *network.Receiver,
	parameters Parameters,
	committee Committee,
) *Transmitor {

	tr := &Transmitor{
		sender:   sender,
		receiver: receiver,
		// mempoolCh:  make(chan Message, 1_000),
		// connectCh:  make(chan Message, 1_000),
		smvbaCh:    make(chan Message, 1_000),
		recvCh:     make(chan Message, 1_000),
		msgCh:      make(chan *network.NetMessage, 1_000),
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
			// case "mempool":
			// 	tr.mempoolCh <- msg
			case "consensus":
				tr.recvCh <- msg
			//logger.Warn.Printf(" recvCh 长度：%d", len(tr.smvbaCh))
			case "sMVBA":
				tr.smvbaCh <- msg
				logger.Warn.Printf(" smvbaCh 长度：%d", len(tr.smvbaCh))
			}
		}
	}()

	return tr
}

func (tr *Transmitor) Send(from, to NodeID, msg Message) error {
	var addr []string

	if to == NONE {
		addr = tr.committee.BroadCast(from)
	} else {
		addr = append(addr, tr.committee.Address(to))
	}

	// filter
	// if tr.parameters.DDos && msg.MsgType() == ProposeMsgType {
	// 	time.AfterFunc(time.Millisecond*time.Duration(tr.parameters.NetwrokDelay), func() {
	// 		tr.msgCh <- &network.NetMessage{
	// 			Msg:     msg,
	// 			Address: addr,
	// 		}
	// 	})
	// } else {
	// 	tr.msgCh <- &network.NetMessage{
	// 		Msg:     msg,
	// 		Address: addr,
	// 	}
	// }
	tr.msgCh <- &network.NetMessage{
		Msg:     msg,
		Address: addr,
	}

	return nil
}

func (tr *Transmitor) Recv() Message {
	return <-tr.recvCh
}

func (tr *Transmitor) RecvChannel() chan Message {
	return tr.recvCh
}

func (tr *Transmitor) SMVBARecvChannel() chan Message {
	return tr.smvbaCh
}

// func (tr *Transmitor) MempololRecvChannel() chan Message { //mempool部分的消息通道
// 	return tr.mempoolCh
// }

// func (tr *Transmitor) ConnectRecvChannel() chan Message { //mempool部分的消息通道
// 	return tr.connectCh
// }
