package store

import "errors"

type DB interface {
	Put(key []byte, val []byte) error
	Get(key []byte) ([]byte, error)
}

var (
	ErrNotFoundKey = errors.New("not found key")
)

const (
	READ = iota
	WRITE
	NOTIFYREAD
)

type storeReq struct {
	typ  int
	key  []byte
	val  []byte
	err  error
	Done chan *storeReq
}

func (r *storeReq) done() {
	r.Done <- r
}

type Store struct {
	db    DB
	reqCh chan *storeReq
}

func NewStore(db DB) *Store {
	s := &Store{
		db:    db,
		reqCh: make(chan *storeReq, 1000),
	}
	pending := make(map[string][]*storeReq) //存放等待读取的request
	go func() {
		for req := range s.reqCh {
			switch req.typ {
			case READ:
				{
					val, err := s.db.Get(req.key)
					req.val = val
					req.err = err
					req.Done <- req //提醒说这个请求已经正确存进去了，结束了
				}
			case WRITE:
				{
					//req.err = store.WRITE(req.key, req.val)
					req.err = s.db.Put(req.key, req.val)
					req.Done <- req
					//写进去并且唤醒所有正在等待的人
					if queue, ok := pending[string(req.key)]; ok { //如果有等待的队列消息
						for _, r := range queue {
							r.val = req.val
							r.Done <- r
						}
						delete(pending, string(req.key))
					}
				}
			case NOTIFYREAD:
				{
					if val, err := s.db.Get(req.key); err == nil {
						req.val = val
						req.Done <- req
					} else {
						queue := pending[string(req.key)]
						queue = append(queue, req)
						pending[string(req.key)] = queue
					}
				}
			}
		}
	}()

	return s
}

func (s *Store) Read(key []byte) ([]byte, error) {
	req := &storeReq{
		typ:  READ,
		key:  key,
		Done: make(chan *storeReq, 1),
	}
	s.reqCh <- req
	<-req.Done
	return req.val, req.err
}

func (s *Store) Write(key, val []byte) error {
	req := &storeReq{
		typ:  WRITE,
		key:  key,
		val:  val,
		Done: make(chan *storeReq, 1),
	}
	s.reqCh <- req
	<-req.Done
	return req.err
}

func (s *Store) NotifyRead(key []byte) []byte {
	req := &storeReq{
		typ:  NOTIFYREAD,
		key:  key,
		Done: make(chan *storeReq, 1),
	}
	s.reqCh <- req
	resp := <-req.Done
	return resp.val
}