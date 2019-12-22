package pathtrie

import (
	"regexp"
	"strings"
)

type PathTrie struct {
	exists bool
	trie   map[string]*PathTrie
}

var splitRe = regexp.MustCompile("[.(]")

func (pt *PathTrie) Add(path string) {
	p := splitRe.Split(path, -1)
	head := pt
	for i := 0; !head.exists && i < len(p); i++ {
		if head.trie == nil {
			head.trie = map[string]*PathTrie{}
		}
		if c, ok := head.trie[p[i]]; ok {
			head = c
		} else {
			child := &PathTrie{}
			head.trie[p[i]] = child
			head = child
		}
	}
	head.exists = true
}

func (pt PathTrie) Covers(path string) bool {
	return pt.covers(splitRe.Split(path, -1), 0)
}

func (pt PathTrie) covers(p []string, i int) bool {
	head := &pt
	for {
		if head.exists {
			return true
		}
		if i >= len(p) {
			return false
		}
		// Allow Blah(*).
		if c, ok := head.trie["*)"]; ok {
			// id captured by * might contain . and thus be split - find the end
			var j int
			for j = i; j < len(p) && !strings.HasSuffix(p[j], ")"); {
				j++
			}
			if c.covers(p, j+1) {
				return true
			}
		}
		var ok bool
		head, ok = head.trie[p[i]]
		if !ok {
			return false
		}
		i++
	}
}
