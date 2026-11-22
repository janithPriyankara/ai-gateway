// Package policy evaluates profile rules for tool calls.
//
// Profiles are compiled once into an immutable Engine; Decide is lock-free and
// allocation-free so it can sit on the hot path of every tools/call.
package policy

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
)

// Engine is an immutable, compiled set of profiles plus per-client rate-limit state.
type Engine struct {
	profiles map[string]*compiledProfile
	now      func() time.Time

	mu      sync.Mutex
	windows map[rateKey]*window
}

type compiledProfile struct {
	servers   map[string]struct{}
	rules     []compiledRule
	perMinute int
}

type compiledRule struct {
	glob   glob
	when   domain.When
	action domain.Action
	reason string
}

type rateKey struct{ profile, client string }

type window struct {
	start time.Time
	count int
}

const (
	reasonNoRule        = "no rule matched (default deny)"
	reasonNotInProfile  = "server not in profile"
	reasonNoProfile     = "unknown profile"
	reasonRateLimitedTx = "rate limited"
)

// ReasonRateLimited is the reason used when AllowRate refuses a call.
const ReasonRateLimited = reasonRateLimitedTx

// Validate checks a single profile (spec POL-007).
func Validate(p domain.Profile) error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("profile name is required")
	}
	for i, r := range p.Rules {
		if strings.TrimSpace(r.Tool) == "" {
			return fmt.Errorf("profile %q rule %d: tool pattern is required", p.Name, i+1)
		}
		switch r.Action {
		case domain.ActionAllow, domain.ActionAsk, domain.ActionDeny:
		default:
			return fmt.Errorf("profile %q rule %d: unknown action %q (use allow, ask or deny)", p.Name, i+1, r.Action)
		}
		switch r.When {
		case "", domain.WhenAny, domain.WhenReadOnly, domain.WhenWrite:
		default:
			return fmt.Errorf("profile %q rule %d: unknown when %q (use any, read_only or write)", p.Name, i+1, r.When)
		}
	}
	if p.RateLimit != nil && p.RateLimit.PerMinute < 0 {
		return fmt.Errorf("profile %q: rate_limit.per_minute must be >= 0", p.Name)
	}
	return nil
}

// Compile validates and compiles profiles into an Engine.
func Compile(profiles []domain.Profile) (*Engine, error) {
	e := &Engine{
		profiles: make(map[string]*compiledProfile, len(profiles)),
		now:      time.Now,
		windows:  make(map[rateKey]*window),
	}
	for _, p := range profiles {
		if err := Validate(p); err != nil {
			return nil, err
		}
		if _, dup := e.profiles[p.Name]; dup {
			return nil, fmt.Errorf("duplicate profile name %q", p.Name)
		}
		cp := &compiledProfile{servers: make(map[string]struct{}, len(p.Servers))}
		for _, s := range p.Servers {
			cp.servers[s] = struct{}{}
		}
		for i, r := range p.Rules {
			when := r.When
			if when == "" {
				when = domain.WhenAny
			}
			cp.rules = append(cp.rules, compiledRule{
				glob:   compileGlob(r.Tool),
				when:   when,
				action: r.Action,
				reason: fmt.Sprintf("rule %d (%s, %s) → %s", i+1, r.Tool, when, r.Action),
			})
		}
		if p.RateLimit != nil {
			cp.perMinute = p.RateLimit.PerMinute
		}
		e.profiles[p.Name] = cp
	}
	return e, nil
}

// Decide evaluates the profile for one call (POL-001..POL-006). It does not apply rate limits.
func (e *Engine) Decide(profile, serverID, tool string, readOnly bool) domain.Decision {
	p, ok := e.profiles[profile]
	if !ok {
		return domain.Decision{Action: domain.ActionDeny, RuleIndex: -1, Reason: reasonNoProfile}
	}
	if _, ok := p.servers[serverID]; !ok {
		return domain.Decision{Action: domain.ActionDeny, RuleIndex: -1, Reason: reasonNotInProfile}
	}
	for i := range p.rules {
		r := &p.rules[i]
		switch r.when {
		case domain.WhenReadOnly:
			if !readOnly {
				continue
			}
		case domain.WhenWrite:
			if readOnly {
				continue
			}
		}
		if r.glob.match(tool) {
			return domain.Decision{Action: r.action, RuleIndex: i, Reason: r.reason}
		}
	}
	return domain.Decision{Action: domain.ActionDeny, RuleIndex: -1, Reason: reasonNoRule}
}

// Visible reports whether a tool should appear in tools/list (POL-010).
func (e *Engine) Visible(profile, serverID, tool string, readOnly bool) bool {
	return e.Decide(profile, serverID, tool, readOnly).Action != domain.ActionDeny
}

// HasProfile reports whether the profile exists.
func (e *Engine) HasProfile(name string) bool { _, ok := e.profiles[name]; return ok }

// ProfileServers reports whether serverID belongs to profile.
func (e *Engine) ProfileServers(profile string) map[string]struct{} {
	if p, ok := e.profiles[profile]; ok {
		return p.servers
	}
	return nil
}

// AllowRate applies the profile's per-client rate limit (POL-008).
// It uses a fixed one-minute window per (profile, client).
func (e *Engine) AllowRate(profile, clientID string) bool {
	p, ok := e.profiles[profile]
	if !ok || p.perMinute == 0 {
		return true
	}
	now := e.now()
	k := rateKey{profile, clientID}
	e.mu.Lock()
	defer e.mu.Unlock()
	w := e.windows[k]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &window{start: now}
		e.windows[k] = w
	}
	if w.count >= p.perMinute {
		return false
	}
	w.count++
	return true
}

// glob is a compiled '*'-only, anchored, case-sensitive pattern (POL-003).
type glob struct {
	literal bool // no '*' at all
	parts   []string
}

func compileGlob(pattern string) glob {
	if !strings.Contains(pattern, "*") {
		return glob{literal: true, parts: []string{pattern}}
	}
	return glob{parts: strings.Split(pattern, "*")}
}

func (g glob) match(s string) bool {
	if g.literal {
		return s == g.parts[0]
	}
	first, last := g.parts[0], g.parts[len(g.parts)-1]
	if len(s) < len(first)+len(last) || !strings.HasPrefix(s, first) || !strings.HasSuffix(s, last) {
		return false
	}
	mid := s[len(first) : len(s)-len(last)]
	for _, p := range g.parts[1 : len(g.parts)-1] {
		if p == "" {
			continue
		}
		i := strings.Index(mid, p)
		if i < 0 {
			return false
		}
		mid = mid[i+len(p):]
	}
	return true
}
