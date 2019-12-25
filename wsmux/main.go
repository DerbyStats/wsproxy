package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
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
	kf          *keyfilter.KeyFilter
	externalURL *url.URL
	store       *sessions.CookieStore

	mu        sync.Mutex
	listeners map[string]*proxy.WSListener
}

func NewWSMux(kf *keyfilter.KeyFilter, externalURL *url.URL) *WSMux {
	store := sessions.NewCookieStore([]byte("blah")) // TODO: Secure value.
	store.Options.HttpOnly = true
	// Keep for a year, you should have at least one game in that time
	// which will refresh this.
	store.Options.MaxAge = 86400 * 365
	return &WSMux{
		kf:          kf,
		externalURL: externalURL,
		store:       store,
		listeners:   map[string]*proxy.WSListener{},
	}
}

type ListenerInfo struct {
	Name        string
	LastUpdated time.Time
	Clients     int
	State       map[string]interface{}
}

func (li ListenerInfo) GetString(k string) string {
	v, ok := li.State[k]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func (li ListenerInfo) GetInt(k string) int {
	v, ok := li.State[k]
	if !ok {
		return 0
	}
	i, _ := v.(float64)
	return int(i)
}

func (li ListenerInfo) GetBool(k string) bool {
	v, ok := li.State[k]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
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
		}
	}
}

func (m *WSMux) gc() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for name, l := range m.listeners {
		lu, c, _ := l.Status()
		if c == 0 && lu.Add(time.Hour).Before(now) {
			log.Println("GCing", name)
			delete(m.listeners, name)
		}
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
	l := proxy.NewWSListener(m.kf)
	m.listeners[name] = l
	return l
}

func homepage(w http.ResponseWriter, r *http.Request, wsMux *WSMux, externalURL *url.URL) {
	li := wsMux.Listeners()
	now := time.Now()
	fmt.Fprintf(w, `
  <html>
  <head><title>Live Derby Stats</title></head>
  <body>
  <h1>Live Derby Stats</h1>
  <table border=1 cellpadding="3em" cellspacing="0">
  <tr><th>Name</th><th>Clients</th><th>Summary</th><th>Age</th>
  `)
	for _, l := range li {
		summary := ""
		t1 := l.GetString("ScoreBoard.Team(1).Name")
		if t1 == "" {
			// Connection with no matching pushes.
			continue
		}
		t2 := l.GetString("ScoreBoard.Team(2).Name")
		s1 := l.GetInt("ScoreBoard.Team(1).Score")
		s2 := l.GetInt("ScoreBoard.Team(2).Score")
		official := l.GetBool("ScoreBoard.OfficialScore")
		p := l.GetInt("ScoreBoard.Clock(Period).Number")
		j := l.GetInt("ScoreBoard.Clock(Jam).Number")
		pc := l.GetInt("ScoreBoard.Clock(Period).Time") / 1000
		ic := l.GetInt("ScoreBoard.Clock(Intermission).Time") / 1000
		icr := l.GetBool("ScoreBoard.Clock(Intermission).Running")
		// Have some data.
		summary += fmt.Sprintf(" %s - %s", t1, t2)
		score := fmt.Sprintf("%d - %d", s1, s2)
		if official {
			summary += fmt.Sprintf(", %s, Official Score", score)
		} else if p != 0 {
			// Game has started.
			summary += fmt.Sprintf(", %s, P%d (%d:%02d) J%d", score, p, pc/60, pc%60, j)
		} else if icr {
			summary += fmt.Sprintf(", %d:%02d to Derby", ic/60, ic%60)
		} else {
			summary += fmt.Sprintf(", Not Started")
		}
		u := *externalURL
		u.Host = l.Name + "." + u.Host
		fmt.Fprintf(w, `
    <tr>
    <td><a href="%s">%s</td>
    <td>%d</td>
    <td>%s</td>
    <td>%s</td>
    </tr>`,
			html.EscapeString(u.String()), html.EscapeString(l.Name),
			l.Clients,
			html.EscapeString(summary),
			now.Sub(l.LastUpdated).Round(time.Second*10).String())
	}

	fmt.Fprintf(w, `
  </table>
  <p><a href="https://github.com/DerbyStats/wsproxy">Source Code</a></p>
  </body>
  </html>`)
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

	wsMux := NewWSMux(keyFilter, externalURL)
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

	http.Handle("/", r)
	log.Println("Listening on", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
