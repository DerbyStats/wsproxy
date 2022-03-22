package proxy

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/gorilla/websocket"
	"github.com/juju/persistent-cookiejar"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/DerbyStats/wsproxy/pkg/keyfilter"
	"github.com/DerbyStats/wsproxy/pkg/wsstate"
)

var (
	startedLoops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ds_wsproxy_listener_connections_total",
		Help: "Number of connections initiated.",
	})
	activeLoops = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ds_wsproxy_listener_connections_active",
		Help: "Number of active listener connections.",
	})
	receivedEntries = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "ds_wsproxy_listener_wsstate_entries",
		Help:    "Number of entries in each state WS message we received, after filtering.",
		Buckets: []float64{0, 5, 10, 50, 100, 500, 1000, 5000, 10000},
	})
	filteredEntries = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ds_wsproxy_listener_wsstate_entries_filtered_total",
		Help: "Number of entries WS state entries we filtered.",
	})
	stateFileWriteDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "ds_wsproxy_listener_statefile_write_duration_seconds",
		Help: "How long attempts to write a statefile took.",
	})
	stateFileWritesFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ds_wsproxy_listener_statefile_writes_failed_total",
		Help: "Numer of times a state file write failed.",
	})
	shutdownDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "ds_wsproxy_listener_shutdown_duration_seconds",
		Help: "How long shutdowns have taken.",
	})
)

type wsMessage struct {
	Pong  *string       `json:"Pong,omitempty"`
	Error string        `json:"error,omitempty"`
	State wsstate.State `json:"state,omitempty"`
}

type wsCommand struct {
	Action string   `json:"action,omitempty"`
	Paths  []string `json:"paths,omitempty"`
}

type UpdateListener interface {
	// What just changed and the new full state.
	Update(update, full map[string]interface{})

	// This update source is done, any future updates won't be reported.
	UpdatesDone()
}

// A WSListener represents a connection to a Scoreboard,
// which listens to WS updates and forwards them on.
type WSListener struct {
	ctx       context.Context
	ctxCancel func()
	logger    log.Logger
	kf        *keyfilter.KeyFilter
	stateFile string

	mu         sync.Mutex
	state      wsstate.State // The current state.
	listeners  map[UpdateListener]struct{}
	lastUpdate time.Time
	conn       *websocket.Conn

	loopMu sync.Mutex // Only allow one client loop at a time.
}

func NewWSListener(ctx context.Context, logger log.Logger, kf *keyfilter.KeyFilter, stateFile string) *WSListener {
	c, cancel := context.WithCancel(ctx)
	wsl := &WSListener{
		ctx:       c,
		ctxCancel: cancel,
		logger:    logger,
		kf:        kf,
		stateFile: stateFile,
		listeners: map[UpdateListener]struct{}{},
	}
	wsl.readStateFile()
	return wsl
}

// Run keeps a WS connection open to the given URL.
func (wsl *WSListener) Run(url string, dialer *WSDialer) {
	for {
		c, _, err := dialer.Dial(context.TODO(), url)
		if err != nil {
			level.Error(wsl.logger).Log("msg", "Listener connection error", "err", err)
			// Back off a bit.
			time.Sleep(time.Second * 5)
			continue
		}
		level.Info(wsl.logger).Log("msg", "Listener has dialed connection")
		err = wsl.clientLoop(c)
		if err != nil {
			level.Error(wsl.logger).Log("msg", "Listener loop error", "err", err)
		}
		c.Close()
	}
}

// Receive uses an inbound WS connection. This is an alternative to Run.
func (wsl *WSListener) Receive(w http.ResponseWriter, r *http.Request) {
	logger := log.With(wsl.logger, "remoteAddr", r.RemoteAddr, "X-Forwarded-For", r.Header.Get("X-Forwarded-For"))
	level.Info(logger).Log("msg", "Listener received a WS push connection")
	upgrader := &websocket.Upgrader{}
	c, err := upgrader.Upgrade(w, r, w.Header())
	if err != nil {
		level.Error(logger).Log("msg", "Listener receive upgrade error", "err", err)
		return
	}
	err = wsl.clientLoop(c)
	level.Info(logger).Log("msg", "Listener loop error", "err", err)
	c.Close()
}

func (wsl *WSListener) clientLoop(c *websocket.Conn) error {
	wsl.loopMu.Lock()
	defer wsl.loopMu.Unlock()
	activeLoops.Inc()
	startedLoops.Inc()
	wsl.mu.Lock()
	wsl.conn = c
	wsl.mu.Unlock()
	defer func() {
		activeLoops.Dec()
		wsl.mu.Lock()
		wsl.conn = nil
		wsl.mu.Unlock()
		wsl.writeStateFile()
	}()

	// Check if this listener was already shutdown.
	select {
	case <-wsl.ctx.Done():
		return wsl.ctx.Err()
	default:
	}

	pingerStopped := make(chan struct{}, 0)
	stopPinger := make(chan struct{}, 0)

	// Register everything.
	c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	err := c.WriteMessage(websocket.TextMessage, []byte(`{"action": "Register", "paths": ["ScoreBoard"]}`))
	if err != nil {
		return err
	}
	level.Debug(wsl.logger).Log("msg", "Listener has registered")

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
					level.Debug(wsl.logger).Log("msg", "Ping write error", "err", err)
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

	initial := true
	lastWrite := time.Time{}
	for {
		select {
		case <-pingerStopped:
			return nil
		case <-wsl.ctx.Done():
			return wsl.ctx.Err()
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
		wsl.mu.Lock()
		wsl.lastUpdate = time.Now()
		wsl.mu.Unlock()
		origLen := len(msg.State)
		// Ignore any extra information we may have been sent, such as WS.Client.
		// Also ignore filtered information.
		for k := range msg.State {
			if !strings.HasPrefix(k, "ScoreBoard.") || !wsl.kf.Keep(k) {
				delete(msg.State, k)
				filteredEntries.Inc()
			}
		}
		if origLen > 0 {
			receivedEntries.Observe(float64(len(msg.State)))
		}
		if msg.Error != "" {
			return fmt.Errorf("error from scoreboard: %s", msg.Error)
		} else if len(msg.State) != 0 {
			wsl.mu.Lock()
			newState := make(map[string]interface{}, len(wsl.state))
			if initial {
				for k, v := range msg.State {
					if v == nil {
						// This shouldn't happen.
						delete(newState, k)
					} else {
						newState[k] = v
						if cv, ok := wsl.state[k]; ok && wsstate.ValuesEqual(v, cv) {
							delete(msg.State, k) // Nothing changed.
						}
					}
				}
				// This is the first proper update from this connection, so have to clear out any
				// keys that were previously sent but are not there any more.
				for k := range wsl.state {
					if _, ok := newState[k]; !ok {
						msg.State[k] = nil
					}
				}
				initial = false
			} else {
				for k, v := range wsl.state {
					newState[k] = v
				}
				for k, v := range msg.State {
					if v == nil {
						delete(newState, k)
					} else {
						newState[k] = v
					}
				}
			}
			wsl.state = newState
			for l := range wsl.listeners {
				l.Update(msg.State, newState)
			}
			wsl.mu.Unlock()
		}
		// Write out to disk every 30s or so, in case we crash.
		if lastWrite.Add(time.Second * 30).Before(time.Now()) {
			wsl.writeStateFile()
			lastWrite = time.Now()
		}
	}
}

func (wsl *WSListener) writeStateFile() {
	wsl.mu.Lock()
	defer wsl.mu.Unlock()
	if wsl.stateFile == "" || wsl.lastUpdate.IsZero() {
		return
	}
	timer := prometheus.NewTimer(stateFileWriteDuration)
	err := wsl.state.WriteStateFile(wsl.stateFile)
	timer.ObserveDuration()
	if err != nil {
		stateFileWritesFailed.Inc()
		level.Error(wsl.logger).Log("msg", "Error writing state file", "err", err)
		return
	}
}

func (wsl *WSListener) readStateFile() {
	wsl.mu.Lock()
	defer wsl.mu.Unlock()
	if wsl.stateFile == "" {
		return
	}
	state, err := wsstate.ReadStateFile(wsl.stateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			level.Error(wsl.logger).Log("msg", "Error opening state file", "err", err)
		}
		return
	}
	// The keepFilter may have changed.
	for k := range state {
		if !wsl.kf.Keep(k) {
			delete(state, k)
		}
	}
	wsl.state = state
	fi, err := os.Stat(wsl.stateFile)
	if err != nil {
		level.Error(wsl.logger).Log("msg", "Error stating state file", "err", err)
		return
	}
	wsl.lastUpdate = fi.ModTime()
}

// Shutdown the listener.
func (wsl *WSListener) Shutdown() {
	timer := prometheus.NewTimer(shutdownDuration)
	defer timer.ObserveDuration()
	wsl.ctxCancel()
	wsl.mu.Lock()
	if wsl.conn != nil {
		// Cancel any blocking reads.
		wsl.conn.Close()
	}
	wsl.mu.Unlock()

	// Wait for clientLoop return.
	wsl.loopMu.Lock()
	wsl.loopMu.Unlock()

	// Let any remaining listners know what we're done.
	wsl.mu.Lock()
	for l := range wsl.listeners {
		l.UpdatesDone()
	}
	wsl.mu.Unlock()
}

// AddListener adds a listener.
//
// The initial update will be in the same thread.
func (wsl *WSListener) AddListener(l UpdateListener) {
	select {
	case <-wsl.ctx.Done():
		l.UpdatesDone()
		return
	default:
	}
	wsl.mu.Lock()
	defer wsl.mu.Unlock()

	wsl.listeners[l] = struct{}{}
	l.Update(wsl.state, wsl.state)
}

// RemoveListener removes a listener.
func (wsl *WSListener) RemoveListener(l UpdateListener) {
	wsl.mu.Lock()
	defer wsl.mu.Unlock()

	delete(wsl.listeners, l)
}

func (wsl *WSListener) Status() (time.Time, int, wsstate.State) {
	wsl.mu.Lock()
	defer wsl.mu.Unlock()
	return wsl.lastUpdate, len(wsl.listeners), wsl.state
}

type WSDialer struct {
	dialer    *websocket.Dialer
	cookieJar *cookiejar.Jar
}

func NewWSDialer() (*WSDialer, error) {
	jar, err := cookiejar.New(&cookiejar.Options{
		Filename: ".cookies",
	})
	if err != nil {
		return nil, err
	}

	return &WSDialer{
		cookieJar: jar,
		dialer: &websocket.Dialer{
			HandshakeTimeout: 30 * time.Second,
			Jar:              jar,
		},
	}, nil
}

func (d *WSDialer) Dial(context context.Context, url string) (*websocket.Conn, *http.Response, error) {
	headers := http.Header{}
	headers.Add("User-Agent", "DerbyStats WS Proxy") // TODO: Version.
	c, h, err := d.dialer.DialContext(context, url, headers)
	if err != nil {
		return nil, nil, err
	}
	if err := d.cookieJar.Save(); err != nil {
		return nil, nil, err
	}
	return c, h, nil
}
