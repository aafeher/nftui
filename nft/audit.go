package nft

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/google/nftables"
)

// AuditEnvVar is the environment variable that enables the mutation audit log.
// When it holds a writable file path, every applied ruleset mutation is
// appended to that file as one JSON object per line (JSON Lines). When unset or
// empty, auditing is disabled and nftui behaves exactly as before: no file I/O
// and no measurable overhead on the mutation path.
//
// The log is append-only and the file is created with 0600 permissions. Each
// line is self-contained and suitable for shipping to a SIEM or forwarding to
// syslog by the operating system. nftui never rotates, truncates, or reads the
// file back. If the path cannot be opened, nftui prints one warning on stderr
// and continues without auditing (audit failures must never block firewall
// management).
const AuditEnvVar = "NFTUI_AUDIT_LOG"

// AuditRecord is a single audit-trail entry describing one attempted ruleset
// mutation and its outcome. It is the unit the audit log stores (one JSON
// object per line).
type AuditRecord struct {
	Time     time.Time
	UID      int
	User     string
	SudoUser string
	Op       string
	Target   string
	Result   string
	Err      string
}

// auditJSON is the on-disk shape of an AuditRecord. Keeping it separate lets
// the in-memory record use Go-native types (time.Time) while the serialized
// form stays stable, compact, and SIEM-friendly.
type auditJSON struct {
	Time     string `json:"time"`
	UID      int    `json:"uid"`
	User     string `json:"user,omitempty"`
	SudoUser string `json:"sudo_user,omitempty"`
	Op       string `json:"op"`
	Target   string `json:"target,omitempty"`
	Result   string `json:"result"`
	Err      string `json:"error,omitempty"`
}

// marshalLine renders the record as a single JSON line terminated by '\n'. It
// is pure (no clock, no environment), so the exact wire format can be unit
// tested from a fixed AuditRecord literal. json.Marshal escapes any control
// characters, so the body can never contain an embedded newline.
func (r AuditRecord) marshalLine() ([]byte, error) {
	b, err := json.Marshal(auditJSON{
		Time:     r.Time.UTC().Format(time.RFC3339Nano),
		UID:      r.UID,
		User:     r.User,
		SudoUser: r.SudoUser,
		Op:       r.Op,
		Target:   r.Target,
		Result:   r.Result,
		Err:      r.Err,
	})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// newAuditRecord stamps a record with the current time and the identity of the
// process: the effective UID and its username, plus SUDO_USER when nftui was
// launched through sudo (so the trail names the human operator, not just root).
// A non-nil err makes the result "error" and records the message; nil makes it
// "ok".
func newAuditRecord(op, target string, err error) AuditRecord {
	uid := os.Getuid()
	rec := AuditRecord{
		Time:     time.Now(),
		UID:      uid,
		User:     usernameForUID(uid),
		SudoUser: os.Getenv("SUDO_USER"),
		Op:       op,
		Target:   target,
		Result:   "ok",
	}
	if err != nil {
		rec.Result = "error"
		rec.Err = err.Error()
	}
	return rec
}

// usernameForUID resolves a UID to a login name, returning "" when the lookup
// fails (a numeric UID with no passwd entry, or a cgo-less static build). The
// UID itself is always recorded, so an empty name never loses information.
func usernameForUID(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return ""
}

// fileAuditSink appends audit records to an open file. A nil *fileAuditSink
// means auditing is disabled. Writes are serialized with a mutex; Bubble Tea
// applies mutations from a single goroutine, but the lock keeps the sink safe
// for any future concurrent caller.
type fileAuditSink struct {
	mu sync.Mutex
	f  *os.File
}

// newFileAuditSink opens path for appending, creating it 0600 if absent.
func newFileAuditSink(path string) (*fileAuditSink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &fileAuditSink{f: f}, nil
}

// write appends one record as a JSON line. The single Write of an append-mode
// file descriptor is atomic for line-sized payloads, so concurrent writers
// never interleave a line.
func (s *fileAuditSink) write(rec AuditRecord) error {
	line, err := rec.marshalLine()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.f.Write(line)
	return err
}

// close releases the underlying file. Used by tests; the process otherwise
// holds the descriptor open for its whole lifetime.
func (s *fileAuditSink) close() error {
	if s == nil || s.f == nil {
		return nil
	}
	return s.f.Close()
}

var (
	auditOnce sync.Once
	auditDst  *fileAuditSink
)

// auditSink returns the process-wide audit sink, configured once from the
// environment on first use. It returns nil when auditing is disabled or when
// the configured path could not be opened: auditing fails open, so a
// misconfigured or unwritable log never blocks firewall management.
func auditSink() *fileAuditSink {
	auditOnce.Do(func() {
		path := os.Getenv(AuditEnvVar)
		if path == "" {
			return
		}
		sink, err := newFileAuditSink(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nftui: cannot open audit log %q: %v; auditing disabled\n", path, err)
			return
		}
		auditDst = sink
	})
	return auditDst
}

// auditEvent appends one record describing an attempted mutation to the audit
// log when auditing is enabled; it is a no-op otherwise. Audit write failures
// are ignored (fail open) — losing an audit line must never turn into a failed
// firewall operation. op is a short stable verb ("create-table", "delete-rule",
// …) and target identifies the object acted on. A non-nil err records the
// failure; pass the result of the kernel commit so the trail captures both
// successes and rejected attempts.
func auditEvent(op, target string, err error) {
	sink := auditSink()
	if sink == nil {
		return
	}
	_ = sink.write(newAuditRecord(op, target, err))
}

// swapAuditSink installs s as the active sink, bypassing the env/once wiring,
// and returns a function that restores the previous sink. It exists so tests
// can exercise auditEvent without root or a real environment; production code
// only ever reaches the sink through auditSink.
func swapAuditSink(s *fileAuditSink) func() {
	auditOnce.Do(func() {}) // consume the once so env config cannot later clobber the override
	prev := auditDst
	auditDst = s
	return func() { auditDst = prev }
}

// tableTarget formats a table for an audit target: "<family> <name>".
func tableTarget(t *nftables.Table) string {
	if t == nil {
		return "?"
	}
	return fmt.Sprintf("%s %s", TableFamilyToString(t.Family), t.Name)
}

// chainTarget formats a chain for an audit target: "<family> <table> <chain>".
func chainTarget(t *nftables.Table, chainName string) string {
	return fmt.Sprintf("%s %s", tableTarget(t), chainName)
}

// ruleTarget formats a rule for an audit target, including its kernel handle
// when known: "<family> <table> <chain> handle <h>".
func ruleTarget(r *nftables.Rule) string {
	if r == nil {
		return "?"
	}
	base := chainTarget(r.Table, safeChainName(r.Chain))
	if r.Handle != 0 {
		return fmt.Sprintf("%s handle %d", base, r.Handle)
	}
	return base
}

// safeChainName extracts a chain's name, tolerating a nil chain (a freshly
// built rule may not carry one yet).
func safeChainName(c *nftables.Chain) string {
	if c == nil {
		return "?"
	}
	return c.Name
}
