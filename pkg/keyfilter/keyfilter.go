package keyfilter

import (
	"fmt"
	"regexp"
	"strings"
)

type KeyFilter struct {
	blacklist *regexp.Regexp
}

// New creates a new KeyFilter, which will reject keys matching the given regexes.
// Regexes are anchored at the start.
func New(blacklist []string) (*KeyFilter, error) {
	if len(blacklist) == 0 || len(blacklist) == 1 && blacklist[0] == "" {
		return &KeyFilter{}, nil
	}
	// Combine into one regex for efficiency, but check individual regexs make sense first.
	for _, s := range blacklist {
		if _, err := regexp.Compile(s); err != nil {
			return nil, fmt.Errorf("error compiling regex %q", s)
		}
	}
	return &KeyFilter{
		blacklist: regexp.MustCompile("^(?:(?:" + strings.Join(blacklist, ")|(?:") + ")).*"),
	}, nil
}

func (kf KeyFilter) Keep(k string) bool {
	if strings.HasSuffix(k, "Secret") {
		// The Scoreboard shouldn't even send us these, but play it safe.
		return false
	}
	if kf.blacklist == nil {
		return true
	}
	return !kf.blacklist.MatchString(k)
}
