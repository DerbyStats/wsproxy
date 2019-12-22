package main

import (
	"io"
	"log"
	"net/http"
)

var hostAddr = "localhost:8000"

func proxyStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	url := r.URL
	url.Host = hostAddr
	url.Scheme = "http"
	request, err := http.NewRequestWithContext(r.Context(), "GET", url.String(), nil)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	client := http.Client{}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// TODO: Caching.
	resp, err := client.Do(request)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}
	for k, v := range resp.Header {
		switch k {
		case "ETag", "Server", "Date":
			w.Header()[k] = v
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	wsl, err := newWSListener("ws://" + hostAddr + "/WS")
	if err != nil {
		log.Fatal("newWSListener", err)
	}
	go wsl.Run()

	http.HandleFunc("/WS/", func(w http.ResponseWriter, r *http.Request) { wsHandler(w, r, wsl) })
	http.HandleFunc("/WS", func(w http.ResponseWriter, r *http.Request) { wsHandler(w, r, wsl) })
	http.HandleFunc("/", proxyStatic)
	log.Fatal(http.ListenAndServe(":8001", nil))
}
