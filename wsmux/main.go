package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"gopkg.in/ini.v1"

	"github.com/DerbyStats/wsproxy/pkg/keyfilter"
	"github.com/DerbyStats/wsproxy/pkg/namegen"
	"github.com/DerbyStats/wsproxy/proxy"
)

const (
	cookieName = "wsmux"
)

type WSMux struct {
	ctx         context.Context
	kf          *keyfilter.KeyFilter
	externalURL *url.URL
	store       *sessions.CookieStore

	mu        sync.Mutex
	listeners map[string]*proxy.WSListener
}

func NewWSMux(ctx context.Context, kf *keyfilter.KeyFilter, externalURL *url.URL) *WSMux {
	store := sessions.NewCookieStore([]byte("blah")) // TODO: Secure value.
	store.Options.HttpOnly = true
	// Keep for a year, you should have at least one game in that time
	// which will refresh this.
	store.Options.MaxAge = 86400 * 365
	return &WSMux{
		ctx:         ctx,
		kf:          kf,
		externalURL: externalURL,
		store:       store,
		listeners:   map[string]*proxy.WSListener{},
	}
}

// Listeners returns information about all Listeners, in a sane order.
func (m *WSMux) Listeners() []ListenerInfo {
	m.mu.Lock()
	li := make([]ListenerInfo, 0, len(m.listeners))
	for name, l := range m.listeners {
		lu, c, s := l.Status()
		li = append(li, ListenerInfo{
			Name:        name,
			LastUpdated: lu,
			Clients:     c,
			State:       s,
		})
	}
	m.mu.Unlock()

	// Most clients first, then most recently updated.
	sort.Slice(li, func(i, j int) bool {
		if li[i].Clients == li[j].Clients {
			return li[i].LastUpdated.After(li[j].LastUpdated)
		}
		return li[i].Clients > li[j].Clients
	})
	return li
}

func (m *WSMux) Run() {
	t := time.NewTicker(time.Minute * 5)
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
		if c == 0 && lu.Add(time.Hour).Before(now) {
			todos = append(todos, todo{name: name, l: l})
		}
	}
	m.mu.Unlock()

	for _, t := range todos {
		// Shutdown might take a while, so do it outside the lock.
		t.l.Shutdown()
		m.mu.Lock()
		delete(m.listeners, t.name)
		m.mu.Unlock()
	}
}

func (m *WSMux) Receive(w http.ResponseWriter, r *http.Request) {
	// Ignore error if presented cookie didn't decode, a new one is provided automatically.
	session, _ := m.store.Get(r, cookieName)
	if session.Values["name"] == nil {
		session.Values["id"] = uuid.New().String()
		session.Values["name"] = namegen.Generate()
	}
	if err := session.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("Error saving session: %v", err), http.StatusInternalServerError)
		return
	}
	name := session.Values["name"].(string)
	log.Println("Receiving WS push connection for", name)
	// Just in case, check for directory transversal.
	if filepath.Base(name) != name {
		http.Error(w, fmt.Sprintf("Invalid name: %q", name), http.StatusInternalServerError)
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
	log.Println("Client connection for", subdomain)
	proxy.WSHTTPHandler(w, r, l)
}

func (m *WSMux) getListener(name string) *proxy.WSListener {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.listeners[name]; ok {
		return l
	}
	l := proxy.NewWSListener(m.ctx, m.kf, filepath.Join("data", name, "state.json"))
	m.listeners[name] = l
	return l
}

func main() {
	f := "config.ini"
	// First argument can be an alternate config file.
	if len(os.Args) >= 2 {
		f = os.Args[1]
	}
	cfg, err := ini.ShadowLoad(f)
	if err != nil {
		log.Fatalf("Failed to read config file %q: %v", f, err)
	}
	listenAddr := cfg.Section("").Key("listen_address").String()

	keyFilter, err := keyfilter.New(cfg.Section("").Key("filter_keys").ValueWithShadows())
	if err != nil {
		log.Fatal("keyFilter", err)
	}
	externalURL, err := url.Parse(cfg.Section("").Key("external_url").String())
	if err != nil {
		log.Fatal("externalURL,", err)
	}

	wsMux := NewWSMux(context.TODO(), keyFilter, externalURL)
	go wsMux.Run()

	r := mux.NewRouter()

	r.HandleFunc("/receiver", wsMux.Receive)
	// Serve up WS.
	r.Host("{subdomain}." + externalURL.Host).Path("/WS").HandlerFunc(wsMux.WSHandler)
	r.Host("{subdomain}." + externalURL.Host).Path("/WS/").HandlerFunc(wsMux.WSHandler)

	// Homepage.
	r.Host("www." + externalURL.Host).Path("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		homepage(w, r, wsMux, externalURL)
	})
	// Redirect bare domain to www,
	r.Host(externalURL.Host).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := *externalURL
		u.Host = "www." + u.Host
		http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
	})

	// Static content on subdomains.
	htmlDir := cfg.Section("").Key("subdomain_html_directory").String()
	fs := http.FileServer(http.Dir(htmlDir))
	if htmlDir != "" {
		log.Println("Serving subdomain content from", htmlDir)
	}
	r.Host("{subdomain}." + externalURL.Host).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if htmlDir != "" {
			w.Header().Set("Cache-Control", "no-cache")
			fs.ServeHTTP(w, r)
		} else {
			fmt.Fprintf(w, "No subdomain_html_directory provided.")
		}
	})

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	log.Println("Listening on", listenAddr)
	httpSrv := &http.Server{Addr: listenAddr, Handler: r}
	go httpSrv.ListenAndServe()

	s := <-term
	log.Println("Shutting down, got signal", s)
	go httpSrv.Shutdown(context.Background()) // Stop accepting new connections.
	wsMux.Shutdown()
	log.Println("Shutdown complete")
	os.Exit(0)
}
