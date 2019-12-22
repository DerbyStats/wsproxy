package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/victorspringer/http-cache"
	"github.com/victorspringer/http-cache/adapter/memory"
	"gopkg.in/ini.v1"

	"github.com/DerbyStats/wsproxy/pkg/keyfilter"
)

type staticProxy struct {
	addr string
}

func (sp staticProxy) proxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	// Better to serve an incorrect or stale response than risk overloading the
	// scoreboard, so strip the request down to the minium for caching.
	u := url.URL{
		Scheme: "http",
		Host:   sp.addr,
		Path:   r.URL.EscapedPath(),
	}
	request, err := http.NewRequestWithContext(r.Context(), "GET", u.String(), nil)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	client := http.Client{}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(request)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}
	for k := range resp.Header {
		if k == "Set-Cookie" {
			continue
		}
		v := resp.Header.Get(k)
		if k == "Location" {
			// Ensure redirects don't include the host.
			if u, err := url.Parse(v); err == nil {
				u.Host = ""
				u.Scheme = ""
				v = u.String()
			}
		}
		w.Header().Set(k, v)
	}
	w.WriteHeader(resp.StatusCode)
	if resp.StatusCode/100 == 4 || resp.StatusCode/100 == 5 {
		// Basic tarpitting to limit requests to the scoreboard. Just in case
		// someone tries lots of invalid URLs or other bad queries sequentially.
		time.Sleep(time.Second)
	}
	io.Copy(w, resp.Body)
}

func pushLoop(hostAddr string, wsl *WSListener, d *wsDialer) {
	for {
		c, err := d.Dial(context.TODO(), "ws://"+hostAddr+"/receiver")
		if err != nil {
			log.Println("Push connect error:", err)
			// Back off a bit.
			time.Sleep(time.Second * 5)
			continue
		}
		log.Println("Push connected to", hostAddr)
		wsHandle(c, wsl)
		time.Sleep(time.Second * 5)
	}
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

	wsl, err := newWSListener(keyFilter)
	if err != nil {
		log.Fatal("newWSListener", err)
	}

	wsd, err := newWSDialer()
	if err != nil {
		log.Fatal("newWSDialer", err)
	}

	scoreboardAddr := cfg.Section("").Key("scoreboard_address").String()
	if scoreboardAddr != "" {
		log.Println("Will get updates from", scoreboardAddr)
		// Option 1: Connect out to a scoreboard.
		go wsl.Run("ws://"+scoreboardAddr+"/WS", wsd)

	} else {
		log.Println("No scoreboard_address, waiting for something to push to us.")
		// Option 2: Wait for the connection to come to us.
		http.HandleFunc("/receiver", wsl.Receive)
	}

	// Static content.
	htmlDir := cfg.Section("").Key("html_directory").String()
	if scoreboardAddr != "" && htmlDir == "" {
		log.Println("Proxying static content from", scoreboardAddr)
		// Serve up static content, which only makes sense if we can talk to the scoreboard.
		memory, err := memory.NewAdapter(
			memory.AdapterWithAlgorithm(memory.LRU),
			memory.AdapterWithCapacity(10000), // Number of cache entries.
		)
		if err != nil {
			log.Fatal("memory cache", err)
		}
		cacheClient, err := cache.NewClient(
			cache.ClientWithAdapter(memory),
			cache.ClientWithTTL(1*time.Minute),
		)
		if err != nil {
			log.Fatal("cache client", err)
		}

		sp := staticProxy{addr: scoreboardAddr}
		http.Handle("/", cacheClient.Middleware(http.HandlerFunc(sp.proxy)))
	} else if htmlDir != "" {
		log.Println("Serving static content from", htmlDir)
		http.Handle("/", http.FileServer(http.Dir(htmlDir)))
	} else {
		log.Println("No scoreboard_address or html_directory provided, so no static content will be served.")
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "No scoreboard_address or html_directory provided.")
		})
	}

	// Serve up WS.
	http.HandleFunc("/WS/", func(w http.ResponseWriter, r *http.Request) { wsHTTPHandler(w, r, wsl) })
	http.HandleFunc("/WS", func(w http.ResponseWriter, r *http.Request) { wsHTTPHandler(w, r, wsl) })

	// Pushing to another proxy.
	pushAddr := cfg.Section("").Key("push_address").String()
	if pushAddr != "" {
		log.Println("Pushing to", pushAddr, "configured.")
		go pushLoop(pushAddr, wsl, wsd)
	}

	log.Println("Listening on", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
