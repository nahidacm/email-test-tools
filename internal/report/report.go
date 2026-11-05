// Package report defines the common result format every tool returns.
//
// A Report has two audiences:
//   - Everyone: Headline, Advice and each Step's Summary/Hint are written in
//     plain language.
//   - Technical users: Step.Details and the timestamped Log carry raw protocol
//     traffic, error strings and timings.
package report

import (
	"fmt"
	"sync"
	"time"
)

type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
	Info Status = "info"
	Skip Status = "skip"
)

// rank orders statuses by severity so the worst one wins for the overall result.
func rank(s Status) int {
	switch s {
	case Fail:
		return 4
	case Warn:
		return 3
	case OK:
		return 2
	case Info:
		return 1
	}
	return 0
}

// Step is one stage of a test, e.g. "Connect to server" or "Log in".
type Step struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Status     Status   `json:"status"`
	Summary    string   `json:"summary"`           // plain-language result
	Hint       string   `json:"hint,omitempty"`    // what to do about it
	Details    []string `json:"details,omitempty"` // technical facts
	DurationMs int64    `json:"durationMs"`
	Category   string   `json:"category,omitempty"` // groups steps in multi-area reports
	Target     string   `json:"target,omitempty"`   // host/IP the step is about
	MoreInfo   string   `json:"moreInfo,omitempty"` // link to an explanation

	start time.Time
}

// BeginIn starts a step in a category, about a specific target.
func (r *Report) BeginIn(category, target, id, title string) *Step {
	s := r.Begin(id, title)
	s.Category, s.Target = category, target
	return s
}

// Info sets the "More info" link.
func (s *Step) Info(url string) *Step { s.MoreInfo = url; return s }

// LogLine is one entry of the technical log.
// Dir: ">" sent by us, "<" received, "*" info, "!" error.
type LogLine struct {
	Ms   int64  `json:"ms"`
	Dir  string `json:"dir"`
	Text string `json:"text"`
}

type Report struct {
	Tool       string    `json:"tool"`
	Status     Status    `json:"status"`
	Headline   string    `json:"headline"`
	Advice     string    `json:"advice,omitempty"`
	Steps      []*Step   `json:"steps"`
	Log        []LogLine `json:"log"`
	Data       any       `json:"data,omitempty"`
	StartedAt  time.Time `json:"startedAt"`
	DurationMs int64     `json:"durationMs"`

	mu    sync.Mutex
	start time.Time
}

func New(tool string) *Report {
	now := time.Now()
	return &Report{Tool: tool, StartedAt: now, start: now, Steps: []*Step{}, Log: []LogLine{}}
}

func (r *Report) log(dir, format string, a ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Log = append(r.Log, LogLine{Ms: time.Since(r.start).Milliseconds(), Dir: dir, Text: fmt.Sprintf(format, a...)})
}

func (r *Report) Sent(format string, a ...any)  { r.log(">", format, a...) }
func (r *Report) Recv(format string, a ...any)  { r.log("<", format, a...) }
func (r *Report) Infof(format string, a ...any) { r.log("*", format, a...) }
func (r *Report) Errf(format string, a ...any)  { r.log("!", format, a...) }

// Begin starts a timed step. Call Done/Set on it when finished.
func (r *Report) Begin(id, title string) *Step {
	s := &Step{ID: id, Title: title, Status: Info, start: time.Now()}
	r.mu.Lock()
	r.Steps = append(r.Steps, s)
	r.mu.Unlock()
	r.Infof("── %s", title)
	return s
}

// Add appends an already-finished step.
func (r *Report) Add(s *Step) *Step {
	r.mu.Lock()
	r.Steps = append(r.Steps, s)
	r.mu.Unlock()
	return s
}

// Finish computes the overall status (worst step) and duration.
// Headline/Advice should be set by the caller before or after.
func (r *Report) Finish() *Report {
	worst := Info
	for _, s := range r.Steps {
		if rank(s.Status) > rank(worst) {
			worst = s.Status
		}
	}
	r.Status = worst
	r.DurationMs = time.Since(r.start).Milliseconds()
	return r
}

// Timer helps fill Step.DurationMs.
type Timer struct{ t time.Time }

func StartTimer() Timer            { return Timer{time.Now()} }
func (t Timer) Ms() int64          { return time.Since(t.t).Milliseconds() }
func (s *Step) Took(t Timer) *Step { s.DurationMs = t.Ms(); return s }
func (s *Step) Detail(f string, a ...any) *Step {
	s.Details = append(s.Details, fmt.Sprintf(f, a...))
	return s
}

// Set records the outcome. For steps created with Begin it also stamps the duration.
func (s *Step) Set(st Status, summary, hint string) *Step {
	s.Status, s.Summary, s.Hint = st, summary, hint
	if !s.start.IsZero() {
		s.DurationMs = time.Since(s.start).Milliseconds()
	}
	return s
}
