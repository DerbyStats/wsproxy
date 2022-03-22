package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/victorspringer/http-cache"
	"github.com/victorspringer/http-cache/adapter/memory"
	"gopkg.in/ini.v1"

	"github.com/DerbyStats/wsproxy/pkg/keyfilter"
	"github.com/DerbyStats/wsproxy/proxy"
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
		http.Error(w, "Error making request to scoreboard", http.StatusBadGateway)
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

func pushLoop(url string, wsl *proxy.WSListener, d *proxy.WSDialer, logger log.Logger) {
	for {
		c, r, err := d.Dial(context.TODO(), url)
		if err != nil {
			level.Error(logger).Log("msg", "Push connection error", "err", err)
			// Back off a bit.
			time.Sleep(time.Second * 5)
			continue
		}
		level.Info(logger).Log("msg", "Push connection made")
		display := r.Header.Get("Display-URL")
		if display != "" {
			level.Debug(logger).Log("msg", "Got display URL from push connection", "url", display)
			// Make it really obvious.
			fmt.Printf("\n\nDisplay URL: %s\n\n\n", display)
		}
		err = proxy.WSHandle(c, wsl, logger)
		level.Info(logger).Log("msg", "Push connection closed", "err", err)
	}
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

	wsl := proxy.NewWSListener(context.Background(), logger, keyFilter, "state.json")

	wsd, err := proxy.NewWSDialer()
	if err != nil {
		level.Error(logger).Log("msg", "Error creating WSDialer", "err", err)
		os.Exit(1)
	}

	scoreboardAddr := cfg.Section("").Key("scoreboard_address").String()
	if scoreboardAddr != "" {
		level.Info(logger).Log("msg", "Will get WS updates from scoreboard", "scoreboardAddr", scoreboardAddr)
		// Option 1: Connect out to a scoreboard.
		go wsl.Run("ws://"+scoreboardAddr+"/WS", wsd)

	} else {
		level.Info(logger).Log("msg", "No scoreboard_address, waiting for something to push WS updates to us.")
		// Option 2: Wait for the connection to come to us.
		http.HandleFunc("/receiver", wsl.Receive)
	}

	// Static content.
	htmlDir := cfg.Section("").Key("html_directory").String()
	if scoreboardAddr != "" && htmlDir == "" {
		level.Info(logger).Log("msg", "Proxying static content from scoreboard", "scoreboardAddr", scoreboardAddr)
		// Serve up static content, which only makes sense if we can talk to the scoreboard.
		memory, err := memory.NewAdapter(
			memory.AdapterWithAlgorithm(memory.LRU),
			memory.AdapterWithCapacity(10000), // Number of cache entries.
		)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to create memory cache", "err", err)
			os.Exit(1)
		}
		cacheClient, err := cache.NewClient(
			cache.ClientWithAdapter(memory),
			cache.ClientWithTTL(1*time.Minute),
		)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to create memory cache client", "err", err)
			os.Exit(1)
		}

		sp := staticProxy{addr: scoreboardAddr}
		http.Handle("/", cacheClient.Middleware(http.HandlerFunc(sp.proxy)))
	} else if htmlDir != "" {
		level.Info(logger).Log("msg", "Serving static content from directory", "dir", htmlDir)
		fs := http.FileServer(http.Dir(htmlDir))
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-cache")
			fs.ServeHTTP(w, r)
		})
	} else {
		level.Info(logger).Log("msg", "No scoreboard_address or html_directory provided, so no static content will be served.")
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "No scoreboard_address or html_directory provided.")
		})
	}

	// Serve up WS.
	http.HandleFunc("/WS/", func(w http.ResponseWriter, r *http.Request) { proxy.WSHTTPHandler(w, r, wsl, logger) })

	// Pushing to another proxy.
  for _, pushURL := range cfg.Section("").Key("push_address").ValueWithShadows() {
    if pushURL == "" {
      continue
    }
		if !strings.HasPrefix(pushURL, "wss://") && !strings.HasPrefix(pushURL, "ws://") {
			pushURL = "ws://" + pushURL
		}
		level.Info(logger).Log("msg", "Pushing configured", "pushURL", pushURL)
		go pushLoop(pushURL+"/receiver", wsl, wsd, log.With(logger, "pushURL", pushURL))
  }

	http.Handle("/metrics", promhttp.Handler())

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	listenAddr := cfg.Section("").Key("listen_address").String()
	level.Info(logger).Log("msg", "Listening for HTTP", "addr", listenAddr)
	httpSrv := &http.Server{Addr: listenAddr}
	go func() {
		if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
			level.Error(logger).Log("msg", "Error listening for HTTP", "err", err)
			os.Exit(1)
		}
	}()

	s := <-term
	level.Info(logger).Log("msg", "Shutting down due to signal", "signal", s)
	go httpSrv.Shutdown(context.Background()) // Stop accepting new connections.
	wsl.Shutdown()
	level.Info(logger).Log("msg", "Shutdown complete. Exiting.")
	os.Exit(0)
}
