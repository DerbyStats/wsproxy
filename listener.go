package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type wsMessage struct {
	Pong  *string                `json:"Pong,omitempty"`
	Error string                 `json:"error,omitempty"`
	State map[string]interface{} `json:"state,omitempty"`
}

type wsCommand struct {
	Action string   `json:"action,omitempty"`
	Paths  []string `json:"paths,omitempty"`
}

type UpdateListener interface {
	// What just changed.
	Update(update map[string]interface{})
}

// A WSListener represents a connection to a Scoreboard,
// which listens to WS updates and forwards them on.
type WSListener struct {
	url       string
	cookieJar http.CookieJar // TODO: Presist to disk.
	dialer    *websocket.Dialer

	mu        sync.Mutex
	state     map[string]interface{} // The current state.
	listeners map[UpdateListener]struct{}
}

func newWSListener(url string) (*WSListener, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout: 30 * time.Second,
		Jar:              jar,
	}

	return &WSListener{
		url:       url,
		cookieJar: jar,
		dialer:    dialer,
		state:     map[string]interface{}{},
		listeners: map[UpdateListener]struct{}{},
	}, nil
}

func (wsl *WSListener) Run() {
	for {
		err := wsl.clientLoop()
		if err != nil {
			log.Println("Listener loop:", err)
		}
		// Back off a bit.
		time.Sleep(time.Second * 5)
	}
}

func (wsl *WSListener) clientLoop() error {
	headers := http.Header{}
	headers.Add("User-Agent", "DerbyStats WS Proxy") // TODO: Version.
	c, _, err := wsl.dialer.DialContext(context.TODO(), wsl.url, headers)
	if err != nil {
		return err
	}
	defer c.Close()

	pingerStopped := make(chan struct{}, 0)
	stopPinger := make(chan struct{}, 0)

	// Register everything.
	c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	err = c.WriteMessage(websocket.TextMessage, []byte(`{"action": "Register", "paths": ["ScoreBoard"]}`))
	if err != nil {
		return err
	}

	// Ping to keep the connection alive when there's no
	// data to be transmitted between games.
	go func() {
		t := time.NewTicker(time.Second * 10)
		defer func() {
			t.Stop()
			<-pingerStopped
			close(pingerStopped)
		}()
		for {
			select {
			case <-t.C:
				// Don't block for too long if there's an issue.
				c.SetWriteDeadline(time.Now().Add(time.Second * 30))
				err := c.WriteMessage(websocket.TextMessage, []byte(`{"action": "Ping"}`))
				if err != nil {
					log.Println("Ping error", err)
					return
				}
			case <-stopPinger:
				return
			}
		}
	}()

	log.Println("Connected and registered on", wsl.url)

	initial := true
	for {
		select {
		case <-pingerStopped:
			break
		default:
		}
		// We should get a pong every few seconds, if we're not seeing one then the
		// connection has probably died. We could be more aggressive, but it could
		// just be a poor WiFI setup and trying more often would only increase
		// bandwidth usage and make it worse.
		c.SetReadDeadline(time.Now().Add(time.Second * 30))
		var msg wsMessage
		err := c.ReadJSON(&msg)
		if err != nil {
			return err
		}
		if msg.Error != "" {
			return fmt.Errorf("error from scoreboard: %s", msg.Error)
		} else if len(msg.State) != 0 {
			wsl.mu.Lock()
			if _, ok := msg.State["WS.Client.Id"]; !ok && initial {
				// This is the first proper update from this connection, so have to clear out any
				// keys that were previously send but are not there now.
				withRemoved := map[string]interface{}{}
				for k, v := range msg.State {
					if v == nil {
						// This should't happen, but just in case.
						delete(msg.State, k)
						continue
					}
					withRemoved[k] = v
				}
				for k := range wsl.state {
					if _, ok := msg.State[k]; !ok {
						withRemoved[k] = nil
					}
				}
				for l := range wsl.listeners {
					l.Update(withRemoved)
				}
				wsl.state = msg.State
				initial = false
			} else {
				for k, v := range msg.State {
					if v == nil {
						delete(wsl.state, k)
					} else {
						wsl.state[k] = v
					}
				}
				for l := range wsl.listeners {
					l.Update(msg.State)
				}
			}
			wsl.mu.Unlock()
		}

	}
	return nil
}

// AddListener adds a listener.
//
// The initial update will be in the same thread.
func (wsl *WSListener) AddListener(l UpdateListener) {
	wsl.mu.Lock()
	defer wsl.mu.Unlock()

	wsl.listeners[l] = struct{}{}
	l.Update(wsl.state)
}

// AddListener removes a listener.
func (wsl *WSListener) RemoveListener(l UpdateListener) {
	wsl.mu.Lock()
	defer wsl.mu.Unlock()

	delete(wsl.listeners, l)
}
