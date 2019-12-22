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
	// What just changed and the new full state.
	Update(update, full map[string]interface{})
}

// A WSListener represents a connection to a Scoreboard,
// which listens to WS updates and forwards them on.
type WSListener struct {
	mu        sync.Mutex
	state     map[string]interface{} // The current state.
	listeners map[UpdateListener]struct{}

	loopMu sync.Mutex // Only allow one client loop at a time.
}

func newWSListener() (*WSListener, error) {
	return &WSListener{
		state:     map[string]interface{}{},
		listeners: map[UpdateListener]struct{}{},
	}, nil
}

// Run keeps a WS connection open to the given URL.
func (wsl *WSListener) Run(url string, dialer *wsDialer) {
	for {
		c, err := dialer.Dial(context.TODO(), url)
		if err != nil {
			log.Println("Connect:", err)
			// Back off a bit.
			time.Sleep(time.Second * 5)
			continue
		}
		err = wsl.clientLoop(c)
		if err != nil {
			log.Println("Listener loop:", err)
		}
		c.Close()
		// Back off a bit.
		time.Sleep(time.Second * 5)
	}
}

// Receive uses an inbound WS connection. This is an alternative to Run.
func (wsl *WSListener) Receive(w http.ResponseWriter, r *http.Request) {
	upgrader := &websocket.Upgrader{}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Received a WS push connection")
	wsl.clientLoop(c)
	c.Close()
}

func (wsl *WSListener) clientLoop(c *websocket.Conn) error {
	wsl.loopMu.Lock()
	defer wsl.loopMu.Unlock()
	pingerStopped := make(chan struct{}, 0)
	stopPinger := make(chan struct{}, 0)

	// Register everything.
	c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	err := c.WriteMessage(websocket.TextMessage, []byte(`{"action": "Register", "paths": ["ScoreBoard"]}`))
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
	defer func() {
		close(stopPinger)
	}()

	log.Println("Connected and registered")

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
				// keys that were previously sent but are not there any more.
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
			}
			stateCopy := make(map[string]interface{}, len(wsl.state))
			for k, v := range wsl.state {
				stateCopy[k] = v
			}
			for l := range wsl.listeners {
				l.Update(msg.State, stateCopy)
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
	l.Update(wsl.state, wsl.state)
}

// AddListener removes a listener.
func (wsl *WSListener) RemoveListener(l UpdateListener) {
	wsl.mu.Lock()
	defer wsl.mu.Unlock()

	delete(wsl.listeners, l)
}

type wsDialer struct {
	dialer    *websocket.Dialer
	cookieJar *cookiejar.Jar
}

func newWSDialer() (*wsDialer, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &wsDialer{
		cookieJar: jar,
		dialer: &websocket.Dialer{
			HandshakeTimeout: 30 * time.Second,
			Jar:              jar,
		},
	}, nil
}

func (d *wsDialer) Dial(context context.Context, url string) (*websocket.Conn, error) {
	headers := http.Header{}
	headers.Add("User-Agent", "DerbyStats WS Proxy") // TODO: Version.
	c, _, err := d.dialer.DialContext(context, url, headers)
	return c, err
}
