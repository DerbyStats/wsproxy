package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"gopkg.in/ini.v1"

	"github.com/DerbyStats/wsproxy/pkg/keyfilter"
	"github.com/DerbyStats/wsproxy/proxy"
)

const (
	cookieName = "wsmux"
)

type WSMux struct {
	kf     *keyfilter.KeyFilter
	domain string
	store  *sessions.CookieStore

	mu        sync.Mutex
	listeners map[string]*proxy.WSListener
}

func NewWSMux(kf *keyfilter.KeyFilter, domain string) *WSMux {
	store := sessions.NewCookieStore([]byte("blah")) // TODO: Secure value.
	store.Options.HttpOnly = true
	// Keep for a year, you should have at least one game in that time
	// which will refresh this.
	store.Options.MaxAge = 86400 * 365
	return &WSMux{
		kf:        kf,
		domain:    domain,
		store:     store,
		listeners: map[string]*proxy.WSListener{},
	}
}

func (m *WSMux) Receive(w http.ResponseWriter, r *http.Request) {
	// Ignore error if presented cookie didn't decode, a new one is provided automatically.
	session, _ := m.store.Get(r, cookieName)
	if session.Values["name"] == nil {
		session.Values["id"] = uuid.New().String()
		session.Values["name"] = session.Values["id"] // TODO something human readable.
	}
	if err := session.Save(r, w); err != nil {
		http.Error(w, fmt.Sprintf("Error saving session: %v", err), http.StatusInternalServerError)
		return
	}
	name := session.Values["name"].(string)
	log.Println("Receiving WS push connection for", name)
	listener := m.getListener(name)
	listener.Receive(w, r)
}

func (m *WSMux) WSHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(r.Host, ".", 2)
	if len(parts) < 2 || (parts[1] != m.domain && !strings.HasPrefix(parts[1], m.domain+":")) {
		http.Error(w, fmt.Sprintf("Bad Host: %v", r.Host), http.StatusBadRequest)
		return
	}
	l := m.getListener(parts[0])
	log.Println("Client connection for", parts[0])
	proxy.WSHTTPHandler(w, r, l)
}

func (m *WSMux) getListener(name string) *proxy.WSListener {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.listeners[name]; ok {
		return l
	}
	l := proxy.NewWSListener(m.kf)
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

	mux := NewWSMux(keyFilter, cfg.Section("").Key("domain").String())

	http.HandleFunc("/receiver", mux.Receive)
	// Serve up WS.
	http.HandleFunc("/WS/", mux.WSHandler)
	http.HandleFunc("/WS", mux.WSHandler)

	// Pushing to another proxy.
	log.Println("Listening on", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
