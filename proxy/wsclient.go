package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/DerbyStats/wsproxy/pkg/pathtrie"
)

var (
	startedClients = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ds_wsproxy_client_connections_total",
		Help: "Number of connections handled.",
	})
	activeClients = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ds_wsproxy_client_connections_active",
		Help: "Number of active client connections.",
	})
	registerPaths = promauto.NewSummary(prometheus.SummaryOpts{
		Name: "ds_wsproxy_client_register_paths",
		Help: "Number of paths in register commands.",
	})
	pingCmds = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ds_wsproxy_client_pings_total",
		Help: "Number of pings received.",
	})
	queueFull = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ds_wsproxy_client_update_queue_full_total",
		Help: "How often the update queue was too full to take more updates.",
	})
	sentEntries = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "ds_wsproxy_client_wsstate_entries",
		Help:    "Number of entries in each state WS message we sent.",
		Buckets: []float64{0, 5, 10, 50, 100, 500, 1000, 5000, 10000},
	})
	clientSentBytes = promauto.NewSummary(prometheus.SummaryOpts{
		Name: "ds_wsproxy_client_sent_bytes",
		Help: "Bytes of JSON messages sent to clients. This excludes WS framing.",
	})
)

// wsHandler handles an inbound HTTP WS connection.
func WSHTTPHandler(w http.ResponseWriter, r *http.Request, wsl *WSListener, logger log.Logger) {
	logger = log.With(logger, "remoteAddr", r.RemoteAddr, "X-Forwarded-For", r.Header.Get("X-Forwarded-For"))
	upgrader := &websocket.Upgrader{}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		level.Error(logger).Log("msg", "Error upgrading websocket connection", "err", err)
		return
	}
	err = WSHandle(c, wsl, logger)
	level.Debug(logger).Log("msg", "Error handling websocket connection", "err", err)
}

// wsHandler handles an inbound WS connection.
func WSHandle(c *websocket.Conn, wsl *WSListener, logger log.Logger) error {
	pc := &proxyClient{
		logger: logger,
		c:      c,
		// Allow a small backlog of updates in case we get behind in sending,
		// however for a client that has gone away the TCP send queue will have
		// to fill before we start backing up here.
		pendingUpdates: make(chan map[string]interface{}, 100),
		pong:           make(chan struct{}, 5), // This shouldn't backlog, but allow for a few anyway.
		errCh:          make(chan error, 1),
		done:           make(chan struct{}),
		pt:             pathtrie.PathTrie{},
	}
	startedClients.Inc()
	activeClients.Inc()
	wsl.AddListener(pc)
	err := pc.Handle()
	wsl.RemoveListener(pc)
	activeClients.Dec()
	return err
}

// proxyClient is a WS client connecting to us, looking for WS updates.
type proxyClient struct {
	logger         log.Logger
	c              *websocket.Conn
	pendingUpdates chan map[string]interface{}
	pong           chan struct{}
	errCh          chan error
	done           chan struct{}

	mu    sync.Mutex
	state map[string]interface{}
	pt    pathtrie.PathTrie
}

func (pc *proxyClient) Handle() error {
	level.Debug(pc.logger).Log("msg", "Starting handling for client")
	go pc.sendLoop()
	go pc.readLoop()
	err := <-pc.errCh
	close(pc.done)
	pc.c.Close()
	return err
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
			pingCmds.Inc()
			select {
			case pc.pong <- struct{}{}:
			default:
			}
		case "Register":
			registerPaths.Observe(float64(len(cmd.Paths)))
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
				queueFull.Inc()
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
				sentEntries.Observe(float64(len(filteredUpdate)))
				pc.send(&wsMessage{State: filteredUpdate})
			}
		}
	}
}

func (pc *proxyClient) send(msg *wsMessage) {
	pc.c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	b, err := json.Marshal(msg)
	if err != nil {
		pc.err(err)
		return
	}
	clientSentBytes.Observe(float64(len(b)))
	err = pc.c.WriteMessage(websocket.TextMessage, b)
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
		queueFull.Inc()
		pc.err(errors.New("update queue for client is full"))
	}
}

func (pc *proxyClient) UpdatesDone() {
	pc.err(errors.New("Listener has stopped sending updates."))
}
