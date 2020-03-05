package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/ini.v1"

	"github.com/DerbyStats/wsproxy/pkg/keyfilter"
	"github.com/DerbyStats/wsproxy/pkg/namegen"
	"github.com/DerbyStats/wsproxy/pkg/wsstate"
	"github.com/DerbyStats/wsproxy/proxy"
)

var (
	nameCollisions = promauto.NewSummary(prometheus.SummaryOpts{
		Name: "ds_wsmux_namegen_collisions",
		Help: "Number of collisions encountered when generating a name.",
	})
	invalidCookies = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ds_wsmux_session_cookies_invalid_total",
		Help: "Number of invalid cookies presented.",
	})
	newListenerDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "ds_wsmux_new_listener_duration_seconds",
		Help: "Time to create new listeners.",
	})
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "ds_wsmux_http_duration_seconds",
		Help: "Duration of non-WS HTTP requests.",
	}, []string{"host", "path"})
	httpBytes = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name: "ds_wsmux_http_response_bytes",
		Help: "Bytes sent in non-WS HTTP responses.",
	}, []string{"host", "path"})
)

const (
	cookieName     = "wsmux"
	cookieFileName = "cookieId"
)

type WSMux struct {
	ctx         context.Context
	logger      log.Logger
	kf          *keyfilter.KeyFilter
	externalURL *url.URL

	mu sync.Mutex
	// Listeners that are currently active.
	listeners map[string]*proxy.WSListener
	// Potential listeners that are not currently active.
	oldListeners map[string]*ListenerInfo
}

func NewWSMux(ctx context.Context, logger log.Logger, kf *keyfilter.KeyFilter, externalURL *url.URL) *WSMux {
	files, err := filepath.Glob("data/*/state.json")
	if err != nil {
		// Should never happen.
		panic(err)
	}
	oldListeners := map[string]*ListenerInfo{}
	for _, fn := range files {
		li := &ListenerInfo{Name: filepath.Base(filepath.Dir(fn))}
		fi, err := os.Stat(fn)
		li.LastUpdated = fi.ModTime()
		if err != nil {
			level.Debug(logger).Log("msg", "Error stating state file", "path", fn, "err", err)
			continue
		}
		state, err := wsstate.ReadStateFile(fn)
		if err != nil {
			level.Debug(logger).Log("msg", "Error reading state file", "path", fn, "err", err)
			continue
		}
		li.Summary = state.Summary()
		if li.Summary != "" {
			oldListeners[li.Name] = li
		}
	}

	return &WSMux{
		ctx:          ctx,
		logger:       logger,
		kf:           kf,
		externalURL:  externalURL,
		listeners:    map[string]*proxy.WSListener{},
		oldListeners: oldListeners,
	}
}

type ListenerInfo struct {
	Name        string
	LastUpdated time.Time
	Clients     int
	Summary     string
}

// Listeners returns information about all Listeners.
func (m *WSMux) Listeners() []*ListenerInfo {
	m.mu.Lock()
	res := make([]*ListenerInfo, 0, len(m.listeners)+len(m.oldListeners))
	for name, l := range m.listeners {
		lu, c, s := l.Status()
		li := &ListenerInfo{
			Name:        name,
			LastUpdated: lu,
			Clients:     c,
			Summary:     s.Summary(),
		}
		res = append(res, li)
	}
	for _, ol := range m.oldListeners {
		res = append(res, ol)
	}
	m.mu.Unlock()

	return res
}

func (m *WSMux) Run() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			m.gc()
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *WSMux) Shutdown() {
	m.mu.Lock()
	for name, l := range m.listeners {
		l.Shutdown()
		delete(m.listeners, name)
	}
	m.mu.Unlock()
}

func (m *WSMux) gc() {
	m.mu.Lock()
	now := time.Now()
	type todo struct {
		name string
		l    *proxy.WSListener
	}
	todos := []todo{}
	for name, l := range m.listeners {
		lu, c, _ := l.Status()
		if c == 0 && lu.Add(time.Minute*5).Before(now) {
			todos = append(todos, todo{name: name, l: l})
		}
	}
	m.mu.Unlock()

	for _, t := range todos {
		level.Debug(m.logger).Log("msg", "Moving listener to cold storage", "listener", t.name)
		// Shutdown might take a while, so do it outside the lock.
		t.l.Shutdown()
		m.mu.Lock()
		delete(m.listeners, t.name)
		lu, _, state := t.l.Status()
		li := &ListenerInfo{
			Name:        t.name,
			LastUpdated: lu,
		}
		li.Summary = state.Summary()
		if li.Summary != "" {
			// Don't save it if it was never pushed to.
			m.oldListeners[t.name] = li
		}
		m.mu.Unlock()
	}
	if len(todos) > 0 {
		level.Info(m.logger).Log("msg", "Moved listeners to cold storage", "count", len(todos))
	}
}

func readCookie(r *http.Request) (string, string) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 2 {
		invalidCookies.Inc()
		return "", ""
	}
	name := parts[0]
	secret := parts[1]
	// Untrusted user input, check for directory transversal.
	if filepath.Base(name) != name || name == "" {
		invalidCookies.Inc()
		return "", ""
	}
	content, err := ioutil.ReadFile(filepath.Join("data", name, cookieFileName))
	if err != nil {
		invalidCookies.Inc()
		return "", ""
	}
	if string(content) != secret {
		invalidCookies.Inc()
		return "", ""
	}
	// Everything checks out, this is a valid cookie.
	return name, secret
}

func generateName() string {
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join("data", name, cookieFileName))
		return !os.IsNotExist(err)
	}
	// Give a few chances to find a nice name.
	for i := 0; i < 10; i++ {
		name := namegen.Generate()
		if !exists(name) {
			nameCollisions.Observe(float64(i))
			return name
		}
	}
	nameCollisions.Observe(10)
	// Fallback to a UUID.
	return uuid.New().String()
}

func (m *WSMux) getSessionName(w http.ResponseWriter, r *http.Request) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name, secret := readCookie(r)
	if name == "" {
		name = generateName()
		secret = uuid.New().String() // This is based on crypto/rand.
		fn := filepath.Join("data", name, cookieFileName)
		err := os.MkdirAll(filepath.Dir(fn), 0o777)
		if err != nil {
			return "", err
		}
		// Concurrent access isn't a concern, but we don't want to write a partial file.
		f, err := ioutil.TempFile(filepath.Dir(fn), filepath.Base(fn))
		if err != nil {
			return "", err
		}
		defer func() {
			f.Close()
			os.Remove(f.Name())
		}()
		_, err = f.Write([]byte(secret))
		if err != nil {
			return "", err
		}
		err = f.Close()
		if err != nil {
			return "", err
		}
		err = os.Rename(f.Name(), fn)
		if err != nil {
			return "", err
		}
	}
	cookie := &http.Cookie{
		Name:  cookieName,
		Value: name + ":" + secret,
		Path:  "/receiver",
		// A scoreboard should connect at least once per year.
		MaxAge:   86400 * 365,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   m.externalURL.Scheme == "https",
	}
	http.SetCookie(w, cookie)
	return name, nil
}

func (m *WSMux) Receive(w http.ResponseWriter, r *http.Request) {
	name, err := m.getSessionName(w, r)
	if err != nil {
		level.Info(m.logger).Log("msg", "Error getting session", "err", err)
		http.Error(w, fmt.Sprintf("Error getting session: %v", err), http.StatusInternalServerError)
		return
	}
	u := *m.externalURL
	u.Host = name + "." + u.Host
	w.Header().Set("Display-URL", u.String())
	listener := m.getListener(name)
	listener.Receive(w, r)
}

func (m *WSMux) WSHandler(w http.ResponseWriter, r *http.Request) {
	subdomain := mux.Vars(r)["subdomain"]
	l := m.getListener(subdomain)
	proxy.WSHTTPHandler(w, r, l, log.With(m.logger, "listener", subdomain))
}

func (m *WSMux) getListener(name string) *proxy.WSListener {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.listeners[name]; ok {
		return l
	}
	// This does IO, should we move it away from the lock?
	timer := prometheus.NewTimer(newListenerDuration)
	l := proxy.NewWSListener(m.ctx, log.With(m.logger, "listener", name), m.kf, filepath.Join("data", name, "state.json"))
	timer.ObserveDuration()
	m.listeners[name] = l
	delete(m.oldListeners, name)
	return l
}

// Collect implements prometheus.Collector
func (m *WSMux) Collect(ch chan<- prometheus.Metric) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("ds_wsmux_listeners_active",
			"Number of active listeners.", nil, nil),
		prometheus.GaugeValue, float64(len(m.listeners)))
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("ds_wsmux_listeners_old",
			"Number of old non-empty listeners, which are only on disk.", nil, nil),
		prometheus.GaugeValue, float64(len(m.oldListeners)))
}

// Describe implements prometheus.Collector
func (m *WSMux) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(m, ch)
}

// prometheusMiddleware implements mux.MiddlewareFunc.
func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := mux.CurrentRoute(r)
		host, _ := route.GetHostTemplate()
		path, _ := route.GetPathTemplate()
		host = strings.Split(host, ".")[0] // Only need the subdomain.
		var timer *prometheus.Timer
		switch path {
		case "/WS/", "/receiver":
			// Ignore WS paths.
		default:
			timer = prometheus.NewTimer(httpDuration.WithLabelValues(host, path))
			next = promhttp.InstrumentHandlerResponseSize(
				httpBytes.MustCurryWith(prometheus.Labels{"host": host, "path": path}), next)
		}
		next.ServeHTTP(w, r)
		if timer != nil {
			timer.ObserveDuration()
		}
	})
}

func main() {
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	f := "config.ini"
	// First argument can be an alternate config file.
	if len(os.Args) >= 2 {
		f = os.Args[1]
	}
	cfg, err := ini.ShadowLoad(f)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to read config file", "file", f, "err", err)
		os.Exit(1)
	}

	if cfg.Section("").Key("log_level").String() != "debug" {
		logger = level.NewFilter(logger, level.AllowInfo())
	} else {
		logger = level.NewFilter(logger, level.AllowAll())
	}
	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	keyFilter, err := keyfilter.New(cfg.Section("").Key("filter_keys").ValueWithShadows())
	if err != nil {
		level.Error(logger).Log("msg", "Error creating keyFilter", "err", err)
		os.Exit(1)
	}
	externalURL, err := url.Parse(cfg.Section("").Key("external_url").String())
	if err != nil {
		level.Error(logger).Log("msg", "Error parsing external_url", "err", err)
		os.Exit(1)
	}

	wsMux := NewWSMux(context.TODO(), logger, keyFilter, externalURL)
	go wsMux.Run()
	prometheus.MustRegister(wsMux)

	r := mux.NewRouter()
	r.Use(prometheusMiddleware)
	r.Handle("/metrics", promhttp.Handler())

	r.HandleFunc("/receiver", wsMux.Receive)
	// Serve up WS.
	r.Host("{subdomain}." + externalURL.Host).Path("/WS/").HandlerFunc(wsMux.WSHandler)

	// Homepage.
	r.Host("live." + externalURL.Host).Path("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		homepage(w, r, wsMux, externalURL)
	})
	// Redirect bare domain to live,
	r.Host(externalURL.Host).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := *externalURL
		u.Host = "live." + u.Host
		http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
	})

	// Static content on subdomains.
	htmlDir := cfg.Section("").Key("subdomain_html_directory").String()
	fs := http.FileServer(http.Dir(htmlDir))
	if htmlDir != "" {
		level.Debug(logger).Log("msg", "Serving subdomain content", "dir", htmlDir)
	}
	r.Host("{subdomain}." + externalURL.Host).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if htmlDir != "" {
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("X-Robots-Tag", "none")
			fs.ServeHTTP(w, r)
		} else {
			fmt.Fprintf(w, "No subdomain_html_directory provided.")
		}
	})

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	listenAddr := cfg.Section("").Key("listen_address").String()
	level.Info(logger).Log("msg", "Listening for HTTP", "addr", listenAddr)
	httpSrv := &http.Server{Addr: listenAddr, Handler: r}
	go func() {
		if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
			level.Error(logger).Log("msg", "Error listening for HTTP", "err", err)
			os.Exit(1)
		}
	}()

	s := <-term
	level.Info(logger).Log("msg", "Shutting down due to signal", "signal", s)
	go httpSrv.Shutdown(context.Background()) // Stop accepting new connections.
	wsMux.Shutdown()
	level.Info(logger).Log("msg", "Shutdown complete. Exiting.")
	os.Exit(0)
}
