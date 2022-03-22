package namegen

import (
	"math/rand"
	"time"
)

var (
	terms = []string{
		"skater", "jammer", "pivot", "blocker", "alternate", "captain",
		"jam", "period", "timeout", "lineup", "team", "review", "start", "stop",
		"seconds", "whistle", "rolling", "stoppage", "clock", "tweet",

		"illegal", "violation", "target", "blocking", "zone", "position",
		"multiplayer", "pass", "penalty", "score", "trip", "point", "initial",
		"interference", "delay", "procedure", "expulsion", "gross", "foulout", "warning", "block",
		"gaining", "report", "return", "impact", "high", "low", "contact", "direction",
		"clockwise", "impenetrable", "pack", "split", "play", "out", "in", "skating",
		"destruction", "bounds", "failure", "yield", "miscounduct", "false",
		"line", "stay", "lead", "lost", "call", "engagement", "complete", "incomplete", "stand", "done",
		"overtime", "reentry", "insubordination", "unsporting", "cut", "swap", "spectrum",

		"head", "back", "shoulder", "knee", "toe", "torso", "finger", "leg", "chin", "thigh",
		"pads", "mouth", "guard", "wrist", "elbow", "forearm", "hand", "shin", "wheel", "truck",
		"star", "stripe", "helmet", "cover", "toestop", "face", "nose", "uniform", "number",

		"bridge", "goat", "wall", "tripod", "recycle", "runback", "lane", "power",

		"short", "flat", "banked", "minor", "major",
	}
	overflow = []string{"ball", "offside", "touchdown", "goalie", "racket", "grass"}
	rng      = rand.New(rand.NewSource(time.Now().Unix()))
)

func init() {
}

func Generate() string {
	i1 := rng.Intn(len(terms))
	i2 := rng.Intn(len(terms))
	if i1 != i2 {
		return terms[i1] + "-" + terms[i2]
	}
	return terms[i1] + "-" + overflow[rng.Intn(len(overflow))]
}
