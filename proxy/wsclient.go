package proxy

import (
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/DerbyStats/wsproxy/pkg/pathtrie"
)

// wsHandler handles an inbound HTTP WS connection.
func WSHTTPHandler(w http.ResponseWriter, r *http.Request, wsl *WSListener) {
	upgrader := &websocket.Upgrader{}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	WSHandle(c, wsl)
}

// wsHandler handles an inbound WS connection.
func WSHandle(c *websocket.Conn, wsl *WSListener) {
	pc := &proxyClient{
		c: c,
		// Allow a small backlog of updates in case we get behind in sending,
		// however for a client that has gone away the TCP send queue will have
		// to fill before we start backing up here.
		pendingUpdates: make(chan map[string]interface{}, 100),
		pong:           make(chan struct{}, 5), // This shouldn't backlog, but allow for a few anyway.
		errCh:          make(chan error, 1),
		done:           make(chan struct{}),
		pt:             pathtrie.PathTrie{},
	}
	wsl.AddListener(pc)
	pc.Handle()
	wsl.RemoveListener(pc)
}

// proxyClient is a WS client connecting to us, looking for WS updates.
type proxyClient struct {
	c              *websocket.Conn
	pendingUpdates chan map[string]interface{}
	pong           chan struct{}
	errCh          chan error
	done           chan struct{}

	mu    sync.Mutex
	state map[string]interface{}
	pt    pathtrie.PathTrie
}

func (pc *proxyClient) Handle() {
	go pc.sendLoop()
	go pc.readLoop()
	err := <-pc.errCh
	log.Println("proxyClient", err)
	close(pc.done)
	pc.c.Close()
}

func (pc *proxyClient) readLoop() {
	for {
		// A standard client should ping us every 30s.
		pc.c.SetReadDeadline(time.Now().Add(time.Second * 100))
		var cmd wsCommand
		err := pc.c.ReadJSON(&cmd)
		if err != nil {
			pc.err(err)
			return
		}
		switch cmd.Action {
		case "Ping":
			select {
			case pc.pong <- struct{}{}:
			default:
			}
		case "Register":
			pc.mu.Lock()
			// Send on paths just registered, and update trie for future ones.
			added := pathtrie.PathTrie{}
			for _, p := range cmd.Paths {
				added.Add(p)
				pc.pt.Add(p)
			}
			addedState := map[string]interface{}{}
			for k, v := range pc.state {
				if added.Covers(k) {
					addedState[k] = v
				}
			}
			pc.mu.Unlock()
			select {
			case pc.pendingUpdates <- addedState:
			default:
				// We cannot block here, as it'd stop updates for all clients.
				pc.err(errors.New("update queue for client is full"))
			}

		}
		select {
		case <-pc.done:
			return
		default:
		}
	}
}

func (pc *proxyClient) sendLoop() {
	for {
		select {
		case <-pc.done:
			return
		case <-pc.pong:
			msg := ""
			pc.send(&wsMessage{Pong: &msg})
		case update := <-pc.pendingUpdates:
			filteredUpdate := map[string]interface{}{}
			pc.mu.Lock()
			for k, v := range update {
				if pc.pt.Covers(k) {
					filteredUpdate[k] = v
				}
			}
			pc.mu.Unlock()
			if len(filteredUpdate) > 0 {
				pc.send(&wsMessage{State: filteredUpdate})
			}
		}
	}
}

func (pc *proxyClient) send(msg *wsMessage) {
	pc.c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	err := pc.c.WriteJSON(&msg)
	if err != nil {
		pc.err(err)
	}
}

func (pc *proxyClient) err(err error) {
	select {
	case pc.errCh <- err:
	default:
		// Already have an error.
	}
}

func (pc *proxyClient) Update(update, full map[string]interface{}) {
	select {
	case pc.pendingUpdates <- update:
		pc.mu.Lock()
		pc.state = full
		pc.mu.Unlock()
	default:
		// We cannot block here, as it'd stop updates for all clients.
		pc.err(errors.New("update queue for client is full"))
	}
}

func (pc *proxyClient) UpdatesDone() {
	pc.err(errors.New("Listener has stopped sending updates."))
}
