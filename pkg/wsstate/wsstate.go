package wsstate

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// State is WS information from a scoreboard.
type State map[string]interface{}

func (s State) GetString(k string) string {
	v, ok := s[k]
	if !ok {
		return ""
	}
	str, _ := v.(string)
	return str
}

func (s State) GetInt(k string) int {
	v, ok := s[k]
	if !ok {
		return 0
	}
	i, _ := v.(float64)
	return int(i)
}

func (s State) GetBool(k string) bool {
	v, ok := s[k]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func (s State) Summary() string {
	t1 := s.GetString("ScoreBoard.Team(1).Name")
	if t1 == "" {
		// No real state.
		return ""
	}
	t2 := s.GetString("ScoreBoard.Team(2).Name")
	s1 := s.GetInt("ScoreBoard.Team(1).Score")
	s2 := s.GetInt("ScoreBoard.Team(2).Score")
	official := s.GetBool("ScoreBoard.OfficialScore")
	p := s.GetInt("ScoreBoard.Clock(Period).Number")
	j := s.GetInt("ScoreBoard.Clock(Jam).Number")
	pc := s.GetInt("ScoreBoard.Clock(Period).Time") / 1000
	ic := s.GetInt("ScoreBoard.Clock(Intermission).Time") / 1000
	icr := s.GetBool("ScoreBoard.Clock(Intermission).Running")
	summary := fmt.Sprintf(" %s - %s", t1, t2)
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
	return summary
}

func (s State) WriteStateFile(path string) error {
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, 0o777)
	if err != nil {
		return err
	}
	f, err := ioutil.TempFile(dir, filepath.Base(path))
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	err = enc.Encode(s)
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func ReadStateFile(path string) (State, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	enc := json.NewDecoder(f)
	s := State{}
	err = enc.Decode(&s)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ValuesEqual returns if the two values are equal. Can have false negatives.
func ValuesEqual(a, b interface{}) bool {
	switch v := a.(type) {
	case string:
		w, ok := b.(string)
		return ok && w == v
	case float64:
		w, ok := b.(float64)
		return ok && w == v // An exact float match is okay here.
	case bool:
		w, ok := b.(bool)
		return ok && w == v
	default:
		return false
	}
}
