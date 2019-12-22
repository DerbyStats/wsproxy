package main

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// wsHandler handles an inbound WS connection.
func wsHandler(w http.ResponseWriter, r *http.Request, wsl *WSListener) {
	upgrader := &websocket.Upgrader{}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	pc := &proxyClient{
		c: c,
		// Allow a small backlog of updates in case we get behind in sending,
		// however for a client that has gone away the TCP send queue will have
		// to fill before we start backing up here.
		pendingUpdates: make(chan map[string]interface{}, 100),
		pong:           make(chan struct{}, 5), // This shouldn't backlog, but allow for a few anyway.
		errCh:          make(chan error, 1),
		done:           make(chan struct{}),
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
		}
		if cmd.Action == "Ping" {
			select {
			case pc.pong <- struct{}{}:
			default:
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
			pc.send(&wsMessage{State: update})
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

func (pc *proxyClient) Update(update map[string]interface{}) {
	select {
	case pc.pendingUpdates <- update:
	default:
		// We cannot block here, as it'd stop updates for all clients.
		pc.err(errors.New("update queue for client is full"))
	}
}
