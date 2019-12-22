package main

import (
	"log"
	"net/http"
)

func main() {
	wsl, err := newWSListener("ws://localhost:8000/WS")
	if err != nil {
		log.Fatal("newWSListener", err)
	}
	go wsl.Run()

	http.HandleFunc("/WS", func(w http.ResponseWriter, r *http.Request) { wsHandler(w, r, wsl) })
	log.Fatal(http.ListenAndServe(":8001", nil))
}
