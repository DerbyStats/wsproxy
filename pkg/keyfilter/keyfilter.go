package keyfilter

import (
	"fmt"
	"regexp"
	"strings"
)

type KeyFilter struct {
	rejectlist *regexp.Regexp
}

// New creates a new KeyFilter, which will reject keys matching the given regexes.
// Regexes are anchored at the start.
func New(rejectlist []string) (*KeyFilter, error) {
	if len(rejectlist) == 0 || len(rejectlist) == 1 && rejectlist[0] == "" {
		return &KeyFilter{}, nil
	}
	// Combine into one regex for efficiency, but check individual regexs make sense first.
	for _, s := range rejectlist {
		if _, err := regexp.Compile(s); err != nil {
			return nil, fmt.Errorf("error compiling regex %q", s)
		}
	}
	return &KeyFilter{
		rejectlist: regexp.MustCompile("^(?:(?:" + strings.Join(rejectlist, ")|(?:") + ")).*"),
	}, nil
}

func (kf KeyFilter) Keep(k string) bool {
	if strings.HasSuffix(k, "Secret") {
		// The Scoreboard shouldn't even send us these, but play it safe.
		return false
	}
	if kf.rejectlist == nil {
		return true
	}
	return !kf.rejectlist.MatchString(k)
}
