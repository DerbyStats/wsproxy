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

	fmt.Fprintf(w, "%s", `
  <html>
  <head>
  <title>Live Derby Stats</title>
  <style>
  body {
    background-color: #c1946a;
    color: #dddddd;
    margin: 0;
    font-family: sans-serif;
  }

  .heading {
    font-family: serif;
    text-align: center;
    color: #82b74b;
    background-color: #3e4444;
  }
  h1 {
    margin-bottom: 0;
    font-size: 300%;
  }
  .subtitle {
    font-size: 110%;
    font-style: italic;
  }

  .main {
    margin: 0;
    padding: 2ex;
    background-color: #405d27;
    margin-left: 10%;
    margin-right: 10%;
  }
  .main a {
    color: #eeeeee;
  }
  .main table a {
    font-weight: bolder;
  }

  .footer {
    font-size: 70%;
    text-align: center;
  }
  </style>
  </head>
  <body>
  <div class="heading">
  <h1>DerbyStats: Live</h1>
  <div class="subtitle">Roller Derby Scoreboards in Real Time</div>
  </div>
  <div class="main">
  `)
	if len(active) > 0 {
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
		fmt.Fprintf(w, `
    `)
	} else {
		fmt.Fprintf(w, `<p>There are currently no active scoreboards.</p>`)
	}
	fmt.Fprintf(w,
		`<p>To appear here, ensure the scoreboard computer can access the internet, <a
  href="https://github.com/DerbyStats/wsproxy/releases">download the wsproxy-binaries.zip</a> to the computer running
  your scoreboard, extract it, and run the appropriate binary (Darwin = Mac OS X). You can be up and running in under a minute!</p>
  `)

	if len(inactive) != 0 {
		fmt.Fprintf(w, `
    <p>You can also view inactive scoreboards that have not recently sent updates:<p>
    <table border=1 cellpadding="3em" cellspacing="0">
    <tr><th>Name</th><th>Summary</th><th>Age</th>`)
		for _, l := range inactive {
			u := *externalURL
			u.Host = l.Name + "." + u.Host
			age := now.Sub(l.LastUpdated).Round(time.Minute).String()
			fmt.Fprintf(w, `
      <tr>
      <td><a href="%s/views/standard/">%s</td>
      <td>%s</td>
      <td style="text-align: right;">%s</td>
      </tr>`,
				html.EscapeString(u.String()), html.EscapeString(l.Name),
				html.EscapeString(l.Summary),
				strings.TrimSuffix(age, "0s"))
		}
	}

	fmt.Fprintf(w, `
  </table>
  <div class="footer"><a href="https://github.com/DerbyStats/wsproxy">Source Code</a></div>
  </div>
  </body>
  </html>`)
}
