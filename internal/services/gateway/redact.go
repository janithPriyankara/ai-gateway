package gateway

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// secretPatterns are well-known credential formats scrubbed from upstream results (GW-010).
var secretPatterns = regexp.MustCompile(strings.Join([]string{
	`ghp_[A-Za-z0-9]{20,}`,                                          // GitHub classic PAT
	`github_pat_[A-Za-z0-9_]{20,}`,                                  // GitHub fine-grained PAT
	`gh[ousr]_[A-Za-z0-9]{20,}`,                                     // GitHub OAuth / server / refresh tokens
	`xox[abposr]-[A-Za-z0-9-]{10,}`,                                 // Slack
	`sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`,                          // OpenAI / Anthropic style keys
	`AKIA[0-9A-Z]{16}`,                                              // AWS access key id
	`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, // JWT
	`(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}`,
	`gw[ar]?_[A-Za-z0-9_-]{43}`, // this gateway's own tokens
}, "|"))

const redacted = "[REDACTED]"

// Redactor scrubs secrets from strings.
type Redactor struct{ extra []string }

// NewRedactor returns a redactor that also removes the given literal values.
func NewRedactor(literals []string) Redactor { return Redactor{extra: literals} }

// String redacts s.
func (r Redactor) String(s string) string {
	for _, lit := range r.extra {
		if lit != "" && strings.Contains(s, lit) {
			s = strings.ReplaceAll(s, lit, redacted)
		}
	}
	return secretPatterns.ReplaceAllString(s, redacted)
}

// Result redacts a tool result in place.
func (r Redactor) Result(res *mcp.CallToolResult) {
	if res == nil {
		return
	}
	for _, c := range res.Content {
		switch v := c.(type) {
		case *mcp.TextContent:
			v.Text = r.String(v.Text)
		case *mcp.EmbeddedResource:
			if v.Resource != nil {
				v.Resource.Text = r.String(v.Resource.Text)
			}
		}
	}
	if res.StructuredContent != nil {
		if b, err := json.Marshal(res.StructuredContent); err == nil {
			clean := r.String(string(b))
			if clean != string(b) {
				var v any
				if json.Unmarshal([]byte(clean), &v) == nil {
					res.StructuredContent = v
				}
			}
		}
	}
}

// Summary renders redacted, truncated call arguments for the audit log and approvals.
func (r Redactor) Summary(args json.RawMessage) string {
	s := r.String(string(args))
	if len(s) > 500 {
		s = s[:497] + "..."
	}
	if s == "" || s == "null" {
		s = "{}"
	}
	return s
}
