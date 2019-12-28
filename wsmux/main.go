package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gopkg.in/ini.v1"

	"github.com/DerbyStats/wsproxy/pkg/keyfilter"
	"github.com/DerbyStats/wsproxy/pkg/namegen"
	"github.com/DerbyStats/wsproxy/pkg/wsstate"
	"github.com/DerbyStats/wsproxy/proxy"
)

const (
	cookieName     = "wsmux"
	cookieFileName = "cookieId"
)

type WSMux struct {
	ctx         context.Context
	kf          *keyfilter.KeyFilter
	externalURL *url.URL

	mu sync.Mutex
	// Listeners that are currently active.
	listeners map[string]*proxy.WSListener
	// Potential listeners that are not currently active.
	oldListeners map[string]*ListenerInfo
}

func NewWSMux(ctx context.Context, kf *keyfilter.KeyFilter, externalURL *url.URL) *WSMux {
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
			continue
		}
		state, err := wsstate.ReadStateFile(fn)
		if err != nil {
			continue
		}
		li.Summary = state.Summary()
		if li.Summary != "" {
			oldListeners[li.Name] = li
		}
	}

	return &WSMux{
		ctx:          ctx,
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
		log.Println("Moving listener to cold storage", t.name)
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
}

func readCookie(r *http.Request) (string, string) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 2 {
		return "", ""
	}
	name := parts[0]
	secret := parts[1]
	// Untrusted user input, check for directory transversal.
	if filepath.Base(name) != name || name == "" {
		return "", ""
	}
	content, err := ioutil.ReadFile(filepath.Join("data", name, cookieFileName))
	if err != nil {
		return "", ""
	}
	if string(content) != secret {
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
			return name
		}
	}
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
		http.Error(w, fmt.Sprintf("Error getting session: %v", err), http.StatusInternalServerError)
		return
	}
	log.Println("Receiving WS push connection for", name)
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
	// This does IO, should we move it away from the lock?
	l := proxy.NewWSListener(m.ctx, m.kf, filepath.Join("data", name, "state.json"))
	m.listeners[name] = l
	delete(m.oldListeners, name)
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
