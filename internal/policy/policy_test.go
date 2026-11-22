package policy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mcp-gateway/mcp-gateway/internal/domain"
)

func coding() domain.Profile {
	return domain.Profile{
		Name:    "coding",
		Servers: []string{"github", "notion"},
		Rules: []domain.Rule{
			{Tool: "*", When: domain.WhenReadOnly, Action: domain.ActionAllow},
			{Tool: "github__merge_*", Action: domain.ActionAsk},
			{Tool: "*__delete_*", Action: domain.ActionDeny},
			{Tool: "github__*", Action: domain.ActionAllow},
		},
	}
}

func mustCompile(t *testing.T, ps ...domain.Profile) *Engine {
	t.Helper()
	e, err := Compile(ps)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return e
}

// spec: POL-001, POL-006
func TestFirstMatchWins(t *testing.T) {
	e := mustCompile(t, coding())
	cases := []struct {
		tool     string
		readOnly bool
		want     domain.Action
		rule     int
	}{
		{"github__list_issues", true, domain.ActionAllow, 0},
		{"github__merge_pull_request", false, domain.ActionAsk, 1},
		{"github__merge_pull_request", true, domain.ActionAllow, 0}, // read-only rule is first
		{"github__delete_repo", false, domain.ActionDeny, 2},
		{"github__create_issue", false, domain.ActionAllow, 3},
	}
	for _, c := range cases {
		d := e.Decide("coding", "github", c.tool, c.readOnly)
		if d.Action != c.want || d.RuleIndex != c.rule {
			t.Errorf("%s ro=%v: got %s rule %d, want %s rule %d", c.tool, c.readOnly, d.Action, d.RuleIndex, c.want, c.rule)
		}
		if d.Reason == "" {
			t.Errorf("%s: empty reason", c.tool)
		}
	}
}

// spec: POL-002, POL-006
func TestDefaultDeny(t *testing.T) {
	e := mustCompile(t, coding())
	d := e.Decide("coding", "notion", "notion__update_page", false)
	if d.Action != domain.ActionDeny || d.RuleIndex != -1 {
		t.Fatalf("got %+v, want default deny with rule -1", d)
	}
	if !strings.Contains(d.Reason, "no rule") {
		t.Errorf("reason %q should explain no rule matched", d.Reason)
	}
}

func TestUnknownProfileDenies(t *testing.T) {
	e := mustCompile(t, coding())
	if d := e.Decide("nope", "github", "github__x", true); d.Action != domain.ActionDeny {
		t.Fatalf("unknown profile must deny, got %+v", d)
	}
}

// spec: POL-003
func TestGlob(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"*", "anything", true},
		{"*", "", true},
		{"github__*", "github__list", true},
		{"github__*", "xgithub__list", false},
		{"*__delete_*", "notion__delete_page", true},
		{"*__delete_*", "notion__undelete", false},
		{"a*b*c", "abc", true},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXbYcZ", false},
		{"exact", "exact", true},
		{"exact", "Exact", false}, // case-sensitive
		{"exact", "exactly", false},
		{"**", "x", true},
	}
	for _, c := range cases {
		if got := compileGlob(c.pat).match(c.name); got != c.want {
			t.Errorf("glob(%q).match(%q)=%v want %v", c.pat, c.name, got, c.want)
		}
	}
}

// spec: POL-004
func TestWhen(t *testing.T) {
	p := domain.Profile{Name: "p", Servers: []string{"s"}, Rules: []domain.Rule{
		{Tool: "s__ro", When: domain.WhenReadOnly, Action: domain.ActionAllow},
		{Tool: "s__w", When: domain.WhenWrite, Action: domain.ActionAllow},
		{Tool: "s__any", Action: domain.ActionAllow},
	}}
	e := mustCompile(t, p)
	check := func(tool string, ro bool, want domain.Action) {
		t.Helper()
		if d := e.Decide("p", "s", tool, ro); d.Action != want {
			t.Errorf("%s ro=%v: got %s want %s", tool, ro, d.Action, want)
		}
	}
	check("s__ro", true, domain.ActionAllow)
	check("s__ro", false, domain.ActionDeny)
	check("s__w", false, domain.ActionAllow)
	check("s__w", true, domain.ActionDeny)
	check("s__any", true, domain.ActionAllow)
	check("s__any", false, domain.ActionAllow)
}

// spec: POL-005
func TestServerNotInProfile(t *testing.T) {
	e := mustCompile(t, coding())
	d := e.Decide("coding", "slack", "slack__post", true) // "*" read_only rule would match
	if d.Action != domain.ActionDeny {
		t.Fatalf("server outside profile must be denied, got %+v", d)
	}
	if !strings.Contains(d.Reason, "not in profile") {
		t.Errorf("reason %q", d.Reason)
	}
}

// spec: POL-007
func TestValidation(t *testing.T) {
	bad := []domain.Profile{
		{Name: "", Servers: nil},
		{Name: "a", Rules: []domain.Rule{{Tool: "x", Action: "maybe"}}},
		{Name: "a", Rules: []domain.Rule{{Tool: "x", When: "sometimes", Action: domain.ActionAllow}}},
		{Name: "a", Rules: []domain.Rule{{Tool: "", Action: domain.ActionAllow}}},
		{Name: "a", RateLimit: &domain.RateLimit{PerMinute: -1}},
	}
	for i, p := range bad {
		if _, err := Compile([]domain.Profile{p}); err == nil {
			t.Errorf("case %d: expected validation error for %+v", i, p)
		}
	}
	if _, err := Compile([]domain.Profile{{Name: "dup"}, {Name: "dup"}}); err == nil {
		t.Error("duplicate profile names must be rejected")
	}
	if err := Validate(coding()); err != nil {
		t.Errorf("valid profile rejected: %v", err)
	}
}

// spec: POL-008
func TestRateLimitPerClient(t *testing.T) {
	p := coding()
	p.RateLimit = &domain.RateLimit{PerMinute: 3}
	e := mustCompile(t, p)
	now := time.Unix(1000, 0)
	e.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !e.AllowRate("coding", "client-a") {
			t.Fatalf("call %d should be allowed", i)
		}
	}
	if e.AllowRate("coding", "client-a") {
		t.Fatal("4th call within a minute should be rate limited")
	}
	if !e.AllowRate("coding", "client-b") {
		t.Fatal("limits are per client: client-b must not be affected")
	}
	now = now.Add(61 * time.Second)
	if !e.AllowRate("coding", "client-a") {
		t.Fatal("limit should reset after the window")
	}
	// No rate limit configured: always allowed.
	e2 := mustCompile(t, coding())
	for i := 0; i < 1000; i++ {
		if !e2.AllowRate("coding", "c") {
			t.Fatal("no limit configured must always allow")
		}
	}
}

// spec: POL-010
func TestVisible(t *testing.T) {
	e := mustCompile(t, coding())
	if !e.Visible("coding", "github", "github__create_issue", false) {
		t.Error("allowed tool must be visible")
	}
	if !e.Visible("coding", "github", "github__merge_pr", false) {
		t.Error("ask tool must be visible")
	}
	if e.Visible("coding", "github", "github__delete_repo", false) {
		t.Error("denied tool must be hidden")
	}
	if e.Visible("coding", "slack", "slack__list", true) {
		t.Error("tool on server outside profile must be hidden")
	}
}

// spec: POL-009
func BenchmarkDecide50Rules(b *testing.B) {
	rules := make([]domain.Rule, 0, 50)
	for i := 0; i < 49; i++ {
		rules = append(rules, domain.Rule{Tool: fmt.Sprintf("srv%d__*_thing_%d", i, i), Action: domain.ActionDeny})
	}
	rules = append(rules, domain.Rule{Tool: "*", Action: domain.ActionAllow})
	e, _ := Compile([]domain.Profile{{Name: "p", Servers: []string{"github"}, Rules: rules}})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Decide("p", "github", "github__create_issue_now", false)
	}
}

// spec: POL-009
func TestDecideIsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	r := testing.Benchmark(BenchmarkDecide50Rules)
	if per := time.Duration(r.NsPerOp()); per > 2*time.Microsecond {
		t.Fatalf("Decide took %v per op, budget is 2µs", per)
	}
	if r.AllocsPerOp() > 0 {
		t.Fatalf("Decide allocates %d times per op, want 0", r.AllocsPerOp())
	}
}
