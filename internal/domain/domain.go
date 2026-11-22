// Package domain holds the plain data types shared by every service.
// It has no dependencies on storage, transport or frameworks.
package domain

import "time"

// Role is a dashboard / Admin API role. Higher roles include lower ones.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

var roleRank = map[Role]int{RoleViewer: 1, RoleMember: 2, RoleAdmin: 3, RoleOwner: 4}

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return roleRank[r] > 0 }

// AtLeast reports whether r grants at least the permissions of min.
func (r Role) AtLeast(min Role) bool { return roleRank[r] >= roleRank[min] && roleRank[r] > 0 }

// Identity is who is calling the MCP endpoint, resolved from a token.
type Identity struct {
	UserID     string `json:"user_id"`
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Profile    string `json:"profile"`
}

// Transport is how the gateway talks to an upstream MCP server.
type Transport string

const (
	TransportHTTP  Transport = "http"
	TransportStdio Transport = "stdio"
)

// Server is an upstream MCP server.
type Server struct {
	ID             string    `json:"id" yaml:"id"`
	Name           string    `json:"name" yaml:"name"`
	Prefix         string    `json:"prefix" yaml:"prefix"`
	Transport      Transport `json:"transport" yaml:"transport"`
	URL            string    `json:"url,omitempty" yaml:"url,omitempty"`
	Command        string    `json:"command,omitempty" yaml:"command,omitempty"`
	Args           []string  `json:"args,omitempty" yaml:"args,omitempty"`
	AuthKind       string    `json:"auth_kind" yaml:"auth_kind"` // none | bearer | header | env | oauth
	Enabled        bool      `json:"enabled" yaml:"enabled"`
	TimeoutSeconds int       `json:"timeout_seconds,omitempty" yaml:"timeout_seconds,omitempty"`
	Health         string    `json:"health,omitempty" yaml:"-"`
}

// Action is a policy outcome.
type Action string

const (
	ActionAllow Action = "allow"
	ActionAsk   Action = "ask"
	ActionDeny  Action = "deny"
)

// When narrows a rule by the tool's readOnlyHint.
type When string

const (
	WhenAny      When = "any"
	WhenReadOnly When = "read_only"
	WhenWrite    When = "write"
)

// Rule is one policy rule.
type Rule struct {
	Tool   string `json:"tool" yaml:"tool"`
	When   When   `json:"when,omitempty" yaml:"when,omitempty"`
	Action Action `json:"action" yaml:"action"`
}

// RateLimit caps calls per client.
type RateLimit struct {
	PerMinute int `json:"per_minute" yaml:"per_minute"`
}

// Profile is a named policy: which servers, which rules.
type Profile struct {
	Name      string     `json:"name" yaml:"name"`
	Servers   []string   `json:"servers" yaml:"servers"`
	Rules     []Rule     `json:"rules" yaml:"rules"`
	RateLimit *RateLimit `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`
}

// Decision is the result of evaluating policy for one call.
type Decision struct {
	Action    Action `json:"action"`
	RuleIndex int    `json:"rule_index"`
	Reason    string `json:"reason"`
}

// PinStatus is the review state of a tool fingerprint.
type PinStatus string

const (
	PinApproved    PinStatus = "approved"
	PinQuarantined PinStatus = "quarantined"
)

// ToolPin records the trusted fingerprint of an upstream tool.
type ToolPin struct {
	ServerID    string    `json:"server_id"`
	Tool        string    `json:"tool"` // upstream (un-namespaced) name
	Fingerprint string    `json:"fingerprint"`
	Status      PinStatus `json:"status"`
	Description string    `json:"description"`
	ReadOnly    bool      `json:"read_only"`
	// Pending* describe a detected change awaiting review.
	PendingFingerprint string    `json:"pending_fingerprint,omitempty"`
	OldDescription     string    `json:"old_description,omitempty"`
	NewDescription     string    `json:"new_description,omitempty"`
	OldSchema          string    `json:"old_schema,omitempty"`
	NewSchema          string    `json:"new_schema,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// Snapshot is the versioned configuration the gateway runs on.
type Snapshot struct {
	Version  int64     `json:"version"`
	Servers  []Server  `json:"servers"`
	Profiles []Profile `json:"profiles"`
	Pins     []ToolPin `json:"pins"`
}

// Approval status values.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
	ApprovalExpired  = "expired"
)

// Approval is a human decision request created by an "ask" rule.
type Approval struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	ClientID   string    `json:"client_id"`
	ClientName string    `json:"client_name"`
	Profile    string    `json:"profile"`
	ServerID   string    `json:"server_id"`
	Tool       string    `json:"tool"`
	Summary    string    `json:"summary"`
	RuleIndex  int       `json:"rule_index"`
	Status     string    `json:"status"`
	Reason     string    `json:"reason,omitempty"`
	DecidedBy  string    `json:"decided_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	DecidedAt  time.Time `json:"decided_at,omitempty"`
}

// Audit statuses.
const (
	StatusOK      = "ok"
	StatusError   = "error"
	StatusDenied  = "denied"
	StatusTimeout = "timeout"
)

// AuditEvent is one entry in the tamper-evident log.
type AuditEvent struct {
	ID        int64     `json:"id"`
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"` // call | admin
	RequestID string    `json:"request_id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Profile   string    `json:"profile"`
	ServerID  string    `json:"server_id"`
	Tool      string    `json:"tool"`
	Decision  string    `json:"decision"`
	Status    string    `json:"status"`
	LatencyMS int64     `json:"latency_ms"`
	Summary   string    `json:"summary"`
	Hash      string    `json:"hash"`
	PrevHash  string    `json:"prev_hash"`
}

// AuditQuery filters audit events.
type AuditQuery struct {
	Since, Until time.Time
	UserID       string
	ClientID     string
	ServerID     string
	Tool         string
	Decision     string
	Kind         string
	BeforeID     int64 // cursor: return events with id < BeforeID
	Limit        int
}

// User is a dashboard user.
type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// Client is an AI tool registered with the gateway (static token or OAuth client grant).
type Client struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Name       string    `json:"name"`
	Profile    string    `json:"profile"`
	Kind       string    `json:"kind"` // static | oauth
	Prefix     string    `json:"prefix,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	Calls      int64     `json:"calls"` // tool calls in the audit log (filled by the Admin API)
}
