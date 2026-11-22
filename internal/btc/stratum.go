package btc

// The pool side: Bitcoin's stratum v1 (JSON-RPC, one message per line over
// TCP or TLS): mining.subscribe, mining.authorize, mining.set_difficulty,
// mining.notify and mining.submit.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	dialTimeout   = 10 * time.Second
	callTimeout   = 15 * time.Second
	readIdle      = 5 * time.Minute // pools send work every minute or so; silence this long: reconnect
	maxLine       = 64 << 10
	minBackoff    = time.Second
	maxBackoff    = time.Minute
	writeDeadline = 10 * time.Second
)

type dialer func(ctx context.Context, addr string) (net.Conn, error)

func netDialer(ctx context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	if host, ok := strings.CutPrefix(addr, "tls://"); ok {
		td := &tls.Dialer{NetDialer: d}
		return td.DialContext(ctx, "tcp", host)
	}
	return d.DialContext(ctx, "tcp", strings.TrimPrefix(addr, "tcp://"))
}

type rpcMsg struct {
	ID     *uint64         `json:"id"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

func (m rpcMsg) failed() bool { e := strings.TrimSpace(string(m.Error)); return e != "" && e != "null" }

// Run keeps a connection to the pool until ctx ends, reconnecting with backoff.
func (l *Lottery) Run(ctx context.Context) {
	backoff := minBackoff
	for ctx.Err() == nil {
		start := l.now()
		err := l.session(ctx)
		l.mu.Lock()
		l.conn = false
		l.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		l.setErr("pool: " + err.Error())
		if l.now().Sub(start) > maxBackoff {
			backoff = minBackoff
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (l *Lottery) session(ctx context.Context) error {
	conn, err := l.dial(ctx, l.opt.Pool)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	go func() { <-ctx.Done(); conn.Close() }()

	l.mu.Lock()
	l.gen++
	gen := l.gen
	l.en1, l.en2Size, l.diff = nil, 0, 0
	l.mu.Unlock()

	var (
		wmu     sync.Mutex
		nextID  uint64
		pmu     sync.Mutex
		pending = map[uint64]chan rpcMsg{} // answers awaited
		submits = map[uint64]bool{}
	)
	send := func(method string, params []any, wait bool) (chan rpcMsg, error) {
		wmu.Lock()
		defer wmu.Unlock()
		nextID++
		id := nextID
		var ch chan rpcMsg
		pmu.Lock()
		if wait {
			ch = make(chan rpcMsg, 1)
			pending[id] = ch
		} else if method == "mining.submit" {
			if len(submits) == submitQueue {
				pmu.Unlock()
				return nil, errors.New("pool has too many unanswered shares")
			}
			submits[id] = true
		}
		pmu.Unlock()
		p, _ := json.Marshal(params)
		b, _ := json.Marshal(rpcMsg{ID: &id, Method: method, Params: p})
		conn.SetWriteDeadline(time.Now().Add(writeDeadline))
		_, err := conn.Write(append(b, '\n'))
		return ch, err
	}
	call := func(method string, params ...any) (rpcMsg, error) {
		ch, err := send(method, params, true)
		if err != nil {
			return rpcMsg{}, err
		}
		select {
		case m := <-ch:
			if m.failed() {
				return m, fmt.Errorf("%s refused: %s", method, m.Error)
			}
			return m, nil
		case <-ctx.Done():
			return rpcMsg{}, errors.New("connection closed")
		case <-time.After(callTimeout):
			return rpcMsg{}, fmt.Errorf("%s: no answer", method)
		}
	}

	// Reader: notifications and answers.
	readErr := make(chan error, 1)
	readerDone := make(chan struct{})
	defer func() {
		cancel()
		<-readerDone
	}()
	go func() {
		defer close(readerDone)
		sc := bufio.NewScanner(conn)
		sc.Buffer(make([]byte, 4096), maxLine)
		for {
			conn.SetReadDeadline(time.Now().Add(readIdle))
			if !sc.Scan() {
				err := sc.Err()
				if err == nil {
					err = errors.New("connection closed")
				}
				readErr <- err
				cancel()
				return
			}
			var m rpcMsg
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			if m.Method != "" {
				l.notification(m, gen)
				continue
			}
			if m.ID == nil {
				continue
			}
			pmu.Lock()
			ch, isSubmit := pending[*m.ID], submits[*m.ID]
			delete(pending, *m.ID)
			delete(submits, *m.ID)
			pmu.Unlock()
			switch {
			case ch != nil:
				ch <- m
			case isSubmit:
				var ok bool
				if m.failed() || json.Unmarshal(m.Result, &ok) != nil || !ok {
					l.stats.rejected.Add(1)
					l.setErr("share rejected: " + string(m.Error))
				} else {
					l.stats.accepted.Add(1)
				}
			}
		}
	}()

	sub, err := call("mining.subscribe", l.opt.Agent)
	if err != nil {
		return err
	}
	var res []json.RawMessage
	var en1 string
	var size int
	if json.Unmarshal(sub.Result, &res) != nil || len(res) < 3 || json.Unmarshal(res[1], &en1) != nil || json.Unmarshal(res[2], &size) != nil {
		return errors.New("mining.subscribe: malformed result")
	}
	b, err := hex.DecodeString(en1)
	if err != nil || size < 1 || size > 16 {
		return errors.New("mining.subscribe: bad extranonce")
	}
	l.mu.Lock()
	l.en1, l.en2Size = b, size
	for _, j := range l.jobs { // jobs that arrived before the answer
		if j.gen == gen && j.en1 == nil {
			j.en1, j.en2Size = b, size
		}
	}
	l.mu.Unlock()
	auth, err := call("mining.authorize", l.opt.User, l.opt.Password)
	if err != nil {
		return err
	}
	var ok bool
	if json.Unmarshal(auth.Result, &ok) != nil || !ok {
		return fmt.Errorf("mining.authorize refused for %q", l.opt.User)
	}
	l.mu.Lock()
	l.conn = true
	l.mu.Unlock()
	l.opt.Logf("btc: connected to %s as %s", l.opt.Pool, l.opt.User)

	for {
		select {
		case <-ctx.Done():
			select {
			case err := <-readErr:
				return err
			default:
				return errors.New("connection closed")
			}
		case s := <-l.submits:
			l.mu.Lock()
			current := l.currentLocked(s.job)
			l.mu.Unlock()
			if !current {
				l.stats.dropped.Add(1)
				continue
			}
			if _, err := send("mining.submit", []any{l.opt.User, s.job.poolID, s.en2, s.ntime, s.nonce}, false); err != nil {
				l.stats.dropped.Add(1)
				return err
			}
			l.stats.submitted.Add(1)
			l.opt.Logf("btc: share sent to %s (job %s)", l.opt.Pool, s.job.poolID)
		}
	}
}

// notification handles a message the pool sends on its own.
func (l *Lottery) notification(m rpcMsg, gen uint64) {
	var p []any
	if json.Unmarshal(m.Params, &p) != nil {
		return
	}
	switch m.Method {
	case "mining.set_difficulty":
		if len(p) > 0 {
			if d, ok := p[0].(float64); ok && d > 0 {
				l.mu.Lock()
				l.diff = d
				for _, j := range l.jobs { // jobs that came before any difficulty would never send a share
					if j.gen == gen && j.poolDiff == 0 {
						j.poolDiff = d
					}
				}
				l.mu.Unlock()
			}
		}
	case "mining.notify":
		j, clean, err := parseNotify(p)
		if err != nil {
			l.setErr(err.Error())
			return
		}
		l.addJob(j, clean, gen)
	case "mining.set_extranonce":
		if len(p) >= 2 {
			s, _ := p[0].(string)
			n, _ := p[1].(float64)
			if b, err := hex.DecodeString(s); err == nil && n >= 1 && n <= 16 && n == float64(int(n)) {
				l.mu.Lock()
				l.en1, l.en2Size = b, int(n)
				l.cleanID = l.nextID + 1
				l.mu.Unlock()
			}
		}
	}
}
