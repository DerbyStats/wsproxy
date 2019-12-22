package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/victorspringer/http-cache"
	"github.com/victorspringer/http-cache/adapter/memory"
)

var hostAddr = "localhost:8000"

func proxyStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	// Better to serve an incorrect or stale response than risk overloading the
	// scoreboard, so strip the request down to the minium for caching.
	u := url.URL{
		Scheme: "http",
		Host:   hostAddr,
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
	for k, v := range resp.Header {
		if k != "Set-Cookie" {
			w.Header()[k] = v
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.StatusCode/100 == 4 || resp.StatusCode/100 == 5 {
		// Basic tarpitting to limit requests to the scoreboard. Just in case
		// someone tries lots of invalid URLs or other bad queries sequentially.
		time.Sleep(time.Second)
	}
	io.Copy(w, resp.Body)
}

func pushLoop(hostAddr string, wsl *WSListener) {
	for {
		headers := http.Header{}
		headers.Add("User-Agent", "DerbyStats WS Proxy") // TODO: Version.
		c, _, err := wsl.dialer.DialContext(context.TODO(), "ws://"+hostAddr+"/receiver", headers)
		if err != nil {
			log.Println("Push connect:", err)
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
	wsl, err := newWSListener()
	if err != nil {
		log.Fatal("newWSListener", err)
	}

	// Option 1: Connect out to a scoreboard.
	//  go wsl.Run("ws://" + hostAddr + "/WS")

	// Option 2: Wait for the connection to come to us.
	http.HandleFunc("/receiver", wsl.Receive)

	// Serve up WS.
	http.HandleFunc("/WS/", func(w http.ResponseWriter, r *http.Request) { wsHTTPHandler(w, r, wsl) })

	// go pushLoop("localhost:8001", wsl)

	// Serve up static content.
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

	http.Handle("/", cacheClient.Middleware(http.HandlerFunc(proxyStatic)))
	log.Fatal(http.ListenAndServe(":8001", nil))
}
