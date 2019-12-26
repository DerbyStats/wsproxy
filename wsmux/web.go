package main

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"time"
)

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
