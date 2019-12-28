package main

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func homepage(w http.ResponseWriter, r *http.Request, wsMux *WSMux, externalURL *url.URL) {
	li := wsMux.Listeners()
	active := []*ListenerInfo{}
	inactive := []*ListenerInfo{}
	now := time.Now()

	for _, i := range li {
		if len(i.Summary) == 0 {
			// No useful state.
			continue
		}
		// Active is anything updated in the last 5 minutes.
		if i.LastUpdated.Add(time.Minute * 5).After(now) {
			active = append(active, i)
		} else {
			inactive = append(inactive, i)
		}
	}

	// Most clients first, then most recently updated.
	sort.Slice(active, func(i, j int) bool {
		if active[i].Clients == active[j].Clients {
			return active[i].LastUpdated.After(active[j].LastUpdated)
		}
		return active[i].Clients > active[j].Clients
	})
	// Just most recently updated.
	sort.Slice(inactive, func(i, j int) bool {
		return inactive[i].LastUpdated.After(inactive[j].LastUpdated)
	})

	fmt.Fprintf(w, `
  <html>
  <head><title>Live Derby Stats</title></head>
  <body>
  <h1>Live Derby Stats</h1>
  `)
	if len(active) == 0 {
		fmt.Fprintf(w, `
    <p>There are currently no active scoreboards :(<p>
    `)
	} else {
		if len(active) == 1 {
			fmt.Fprintf(w, `<p>There is currently 1 active scoreboard:</p>`)
		} else {
			fmt.Fprintf(w, `<p>There are currently %d active scoreboards:</p>`, len(active))
		}
		fmt.Fprintf(w, `
    <table border=1 cellpadding="3em" cellspacing="0">
    <tr><th>Name</th><th>Viewers</th><th>Summary</th><th>Age</th>
    `)
		for _, l := range active {
			u := *externalURL
			u.Host = l.Name + "." + u.Host
			fmt.Fprintf(w, `
      <tr>
      <td><a href="%s">%s</td>
      <td style="text-align: center;">%d</td>
      <td>%s</td>
      <td style="text-align: right;">%s</td>
      </tr>`,
				html.EscapeString(u.String()), html.EscapeString(l.Name),
				l.Clients,
				html.EscapeString(l.Summary),
				now.Sub(l.LastUpdated).Round(time.Second*10).String())
		}
		fmt.Fprintf(w, `</table>`)
	}

	fmt.Fprintf(w, `
    <p>There are stats from %d inactive scoreboards:<p>
    <table border=1 cellpadding="3em" cellspacing="0">
    <tr><th>Name</th><th>Summary</th><th>Age</th>`, len(inactive))
	for _, l := range inactive {
		u := *externalURL
		u.Host = l.Name + "." + u.Host
		age := now.Sub(l.LastUpdated).Round(time.Minute).String()
		fmt.Fprintf(w, `
    <tr>
    <td><a href="%s">%s</td>
    <td>%s</td>
    <td style="text-align: right;">%s</td>
    </tr>`,
			html.EscapeString(u.String()), html.EscapeString(l.Name),
			html.EscapeString(l.Summary),
			strings.TrimSuffix(age, "0s"))
	}

	fmt.Fprintf(w, `
  </table>
  <p><a href="https://github.com/DerbyStats/wsproxy">Source Code</a></p>
  </body>
  </html>`)
}
