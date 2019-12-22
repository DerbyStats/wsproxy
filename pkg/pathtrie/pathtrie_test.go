package pathtrie

import (
	"testing"
)

func TestPathTrie(t *testing.T) {
	cases := []struct {
		add       []string
		covered   []string
		uncovered []string
	}{
		{
			add: []string{"ScoreBoard.Period"},
			covered: []string{
				"ScoreBoard.Period",
				"ScoreBoard.Period(1)",
				"ScoreBoard.Period.Jam",
			},
			uncovered: []string{
				"ScoreBoard.PeriodFoo",
				"ScoreBoard.Perioc",
				"ScoreBoard.Perioe",
				"ScoreBoard(1).Perioe",
				"Scoreboard.Period",
				"Foo",
			},
		},
		{
			add: []string{"ScoreBoard.Period(1).Jam(1).StarPass", "ScoreBoard.Period"},
			covered: []string{
				"ScoreBoard.Period",
				"ScoreBoard.Period(1)",
				"ScoreBoard.Period.Jam(1).StarPass",
			},
		},
		{
			add: []string{"ScoreBoard.Period(1).Foo", "ScoreBoard.Period(*).Bar"},
			covered: []string{
				"ScoreBoard.Period(1).Foo",
				"ScoreBoard.Period(1).Bar",
				"ScoreBoard.Period(2).Bar",
			},
			uncovered: []string{
				"ScoreBoard.Period(2).Foo",
			},
		},
		{
			add: []string{"ScoreBoard.Period(*).Jam(1).Foo(*).Bar"},
			covered: []string{
				"ScoreBoard.Period(1).Jam(1).Foo(2).Bar",
				"ScoreBoard.Period(1).Jam(1).Foo(2).Bar.Baz",
				"ScoreBoard.Period(1).Jam(1).Foo(2).Bar(zzz)",
			},
			uncovered: []string{
				"ScoreBoard.Period",
				"ScoreBoard.Period(",
				"ScoreBoard.Period(1)",
				"ScoreBoard.Period(1).Jam(2).Foo(2).Bar",
				"ScoreBoard.Period(1).Jam(2).Foo(2)",
				"ScoreBoard.Period(1).Jam(2).TeamJam(1).Foo(2)",
			},
		},
		{
			add: []string{"ScoreBoard.Period*"},
			covered: []string{
				"ScoreBoard.Period*",
			},
			uncovered: []string{
				"ScoreBoard.Period*a",
				"ScoreBoard.Period",
				"ScoreBoard.Period(",
				"ScoreBoard.Period(1)",
				"ScoreBoard.Period(1).Jam(2).Foo(2).Bar",
			},
		},
		{
			add: []string{
				"ScoreBoard.Rulesets.Rule(Period.Duration)",
				"ScoreBoard.Rulesets.Rule(Jam.*)",
				"ScoreBoard.Rulesets.Rule(Intermission*)",
			},
			covered: []string{
				"ScoreBoard.Rulesets.Rule(Period.Duration)",
				"ScoreBoard.Rulesets.Rule(Jam.Foo)",
				"ScoreBoard.Rulesets.Rule(Jam.Foo.Bar)",
			},
			uncovered: []string{
				"ScoreBoard.Rulesets.Rule(Period.Direction)",
				"ScoreBoard.Rulesets.Rule(Jam)",
				"ScoreBoard.Rulesets.Rule(Intermission.Direction)",
			},
		},
		{
			add: []string{
				"ScoreBoard.Rulesets.Rule(Period.Duration)",
				"ScoreBoard.Rulesets.Rule(Jam.*)",
				"ScoreBoard.Rulesets.Rule(Intermission*)",
				"ScoreBoard.Rulesets.Rule(*)",
			},
			covered: []string{
				"ScoreBoard.Rulesets.Rule(Period.Duration)",
				"ScoreBoard.Rulesets.Rule(Jam.Foo)",
				"ScoreBoard.Rulesets.Rule(Jam.Foo.Bar)",
				"ScoreBoard.Rulesets.Rule(Period.Direction)",
				"ScoreBoard.Rulesets.Rule(Jam)",
				"ScoreBoard.Rulesets.Rule(Intermission.Direction)",
			},
		},
	}
	for _, c := range cases {
		pt := &PathTrie{}
		for _, p := range c.add {
			pt.Add(p)
		}
		for _, p := range c.covered {
			if !pt.Covers(p) {
				t.Errorf("%q was not covered by %v", p, c.add)
			}
		}
		for _, p := range c.uncovered {
			if pt.Covers(p) {
				t.Errorf("%q was covered by %v", p, c.add)
			}
		}
	}
}
