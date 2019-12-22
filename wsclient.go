package main

import (
	"log"
	"net/http"

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
		c:    c,
		done: make(chan struct{}, 0),
	}
	wsl.AddListener(pc)
	pc.Wait()
	wsl.RemoveListener(pc)
}

// proxyClient is a WS client connecting to us, looking for WS updates.
type proxyClient struct {
	c      *websocket.Conn
	done   chan struct{}
	closed bool
}

func (pc *proxyClient) Wait() {
	<-pc.done
}

func (pc *proxyClient) Update(update map[string]interface{}) {
	if pc.closed {
		return
	}
	msg := wsMessage{State: update}
	err := pc.c.WriteJSON(msg)
	if err != nil {
		log.Println(err)
		pc.closed = true
		close(pc.done)
		return
	}
}
