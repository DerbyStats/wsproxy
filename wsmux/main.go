package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
	kf     *keyfilter.KeyFilter
	domain string
	https  bool
	store  *sessions.CookieStore

	mu        sync.Mutex
	listeners map[string]*proxy.WSListener
}

func NewWSMux(kf *keyfilter.KeyFilter, domain string, https bool) *WSMux {
	store := sessions.NewCookieStore([]byte("blah")) // TODO: Secure value.
	store.Options.HttpOnly = true
	// Keep for a year, you should have at least one game in that time
	// which will refresh this.
	store.Options.MaxAge = 86400 * 365
	return &WSMux{
		kf:        kf,
		domain:    domain,
		https:     https,
		store:     store,
		listeners: map[string]*proxy.WSListener{},
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
	url := "http"
	if m.https {
		url += "s"
	}
	url += "://" + name + "." + m.domain + "/"
	w.Header().Set("Display-URL", url)
	listener := m.getListener(name)
	listener.Receive(w, r)
}

func (m *WSMux) WSHandler(w http.ResponseWriter, r *http.Request) {
	if !isDirectSubdomain(r.Host, m.domain) {
		http.Error(w, fmt.Sprintf("Bad Host: %v", r.Host), http.StatusBadRequest)
		return
	}
	parts := strings.Split(r.Host, ".")
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

func isDirectSubdomain(host, domain string) bool {
	parts := strings.SplitN(host, ".", 2)
	return len(parts) == 2 && (parts[1] == domain || strings.HasPrefix(parts[1], domain+":"))
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
	domain := cfg.Section("").Key("domain").String()
	https := cfg.Section("").Key("domain_https").MustBool()

	mux := NewWSMux(keyFilter, domain, https)
	go mux.Run()

	http.HandleFunc("/receiver", mux.Receive)
	// Serve up WS.
	http.HandleFunc("/WS/", mux.WSHandler)
	http.HandleFunc("/WS", mux.WSHandler)

	htmlDir := cfg.Section("").Key("subdomain_html_directory").String()
	fs := http.FileServer(http.Dir(htmlDir))
	if htmlDir != "" {
		log.Println("Serving subdomain content from", htmlDir)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !isDirectSubdomain(r.Host, domain) {
			http.Error(w, fmt.Sprintf("Bad Host: %v", r.Host), http.StatusBadRequest)
			return
		}
		parts := strings.Split(r.Host, ".")
		subdomain := parts[0]
		if subdomain != "www" {
			if htmlDir != "" {
				fs.ServeHTTP(w, r)
			} else {
				fmt.Fprintf(w, "No subdomain_html_directory provided.")
			}
			return
		}

		if r.URL.Path != "/" {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		// Main website.
		li := mux.Listeners()
		now := time.Now()
		fmt.Fprintf(w, `
    <html>
    <head><title>Live Derby Stats</title></head>
    <body>
    <h1>Live Derby Stats</h1>
    <table border=1 cellpadding="3em" cellspacing="0">
    <tr><th>Name</th><th>Clients</th><th>Summary</th><th>Age</th>
    `)
		scheme := "http"
		if https {
			scheme += "s"
		}
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
			fmt.Fprintf(w, `
      <tr>
        <td><a href="%s://%s.%s/">%s</td>
        <td>%d</td>
        <td>%s</td>
        <td>%s</td>
      </tr>`,
				scheme, html.EscapeString(l.Name), domain, html.EscapeString(l.Name),
				l.Clients,
				html.EscapeString(summary),
				now.Sub(l.LastUpdated).Round(time.Second*10).String())
		}

		fmt.Fprintf(w, `
    </table>
    <p><a href="https://github.com/DerbyStats/wsproxy">Source Code</a></p>
    </body>
    </html>`)
	})

	// Pushing to another proxy.
	log.Println("Listening on", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
