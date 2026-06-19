package nft

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAuditRecord_MarshalLine_OK checks the pure on-wire format: a single JSON
// object terminated by exactly one newline, with the timestamp rendered as
// UTC RFC3339 and no error field on a successful record.
func TestAuditRecord_MarshalLine_OK(t *testing.T) {
	rec := AuditRecord{
		Time:   time.Date(2026, 6, 19, 10, 30, 0, 0, time.UTC),
		UID:    0,
		User:   "root",
		Op:     "create-table",
		Target: "ipv4 filter",
		Result: "ok",
	}
	line, err := rec.marshalLine()
	if err != nil {
		t.Fatalf("marshalLine: %v", err)
	}
	if n := len(line); n == 0 || line[n-1] != '\n' {
		t.Fatalf("expected exactly one trailing newline, got %q", string(line))
	}
	// Body (sans newline) must be a single line with no embedded newline.
	if i := indexByte(line[:len(line)-1], '\n'); i >= 0 {
		t.Fatalf("record body contains embedded newline: %q", string(line))
	}
	var got auditJSON
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatalf("unmarshal: %v (line=%q)", err, string(line))
	}
	if got.Op != "create-table" || got.Target != "ipv4 filter" || got.Result != "ok" {
		t.Errorf("unexpected fields: %+v", got)
	}
	if got.Err != "" {
		t.Errorf("ok record must not carry an error, got %q", got.Err)
	}
	if got.Time != "2026-06-19T10:30:00Z" {
		t.Errorf("time = %q, want RFC3339 UTC", got.Time)
	}
}

// TestNewAuditRecord_ErrorResult verifies a non-nil error yields result
// "error" with the message captured, and that identity/time are stamped.
func TestNewAuditRecord_ErrorResult(t *testing.T) {
	rec := newAuditRecord("delete-rule", "ipv4 filter input handle 7", errors.New("boom"))
	if rec.Result != "error" {
		t.Errorf("result = %q, want error", rec.Result)
	}
	if rec.Err != "boom" {
		t.Errorf("err = %q, want boom", rec.Err)
	}
	if rec.UID != os.Getuid() {
		t.Errorf("uid = %d, want %d", rec.UID, os.Getuid())
	}
	if rec.Time.IsZero() {
		t.Errorf("time not stamped")
	}
	if rec.Op != "delete-rule" || rec.Target != "ipv4 filter input handle 7" {
		t.Errorf("op/target not carried: %+v", rec)
	}
}

// TestNewAuditRecord_SudoUser confirms the human operator behind sudo is
// recorded, and a nil error maps to result "ok".
func TestNewAuditRecord_SudoUser(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	rec := newAuditRecord("create-set", "ipv4 filter blocklist", nil)
	if rec.SudoUser != "alice" {
		t.Errorf("sudo_user = %q, want alice", rec.SudoUser)
	}
	if rec.Result != "ok" || rec.Err != "" {
		t.Errorf("nil error must be a clean ok: %+v", rec)
	}
}

// TestFileAuditSink_AppendsJSONLines drives the file sink: two writes must
// append two parseable JSON lines, and the log file must be created 0600.
func TestFileAuditSink_AppendsJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := newFileAuditSink(path)
	if err != nil {
		t.Fatalf("newFileAuditSink: %v", err)
	}
	defer sink.close()

	if err := sink.write(newAuditRecord("create-table", "ipv4 filter", nil)); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := sink.write(newAuditRecord("delete-table", "ipv4 filter", nil)); err != nil {
		t.Fatalf("write 2: %v", err)
	}

	ops := readOps(t, path)
	if len(ops) != 2 {
		t.Fatalf("expected 2 audit lines, got %d: %v", len(ops), ops)
	}
	if ops[0] != "create-table" || ops[1] != "delete-table" {
		t.Errorf("ops = %v, want [create-table delete-table]", ops)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("audit log perm = %o, want 600", perm)
	}
}

// TestAuditEvent_DisabledIsNoop ensures that with no sink configured the audit
// hook does nothing and never panics — the default, behavior-preserving path.
func TestAuditEvent_DisabledIsNoop(t *testing.T) {
	restore := swapAuditSink(nil)
	defer restore()
	auditEvent("create-table", "ipv4 filter", nil) // must be a silent no-op
}

// TestAuditEvent_WritesWhenEnabled exercises the hook end-to-end through a
// temp-file sink installed via the test seam: both an ok and an error event
// must land in the log.
func TestAuditEvent_WritesWhenEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := newFileAuditSink(path)
	if err != nil {
		t.Fatalf("newFileAuditSink: %v", err)
	}
	defer sink.close()
	restore := swapAuditSink(sink)
	defer restore()

	auditEvent("create-table", "ipv4 filter", nil)
	auditEvent("delete-rule", "ipv4 filter input handle 3", errors.New("ruleset changed"))

	ops := readOps(t, path)
	if len(ops) != 2 {
		t.Fatalf("expected 2 audit lines, got %d: %v", len(ops), ops)
	}
	if ops[0] != "create-table" || ops[1] != "delete-rule" {
		t.Errorf("ops = %v", ops)
	}
}

// readAuditRecords reads the audit log and unmarshals every JSON line.
func readAuditRecords(t *testing.T, path string) []auditJSON {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()
	var recs []auditJSON
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec auditJSON
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("line is not valid JSON: %v (%q)", err, sc.Text())
		}
		recs = append(recs, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return recs
}

// readOps reads the audit log and returns the "op" of every JSON line.
func readOps(t *testing.T, path string) []string {
	t.Helper()
	var ops []string
	for _, rec := range readAuditRecords(t, path) {
		ops = append(ops, rec.Op)
	}
	return ops
}

// indexByte is a tiny helper to avoid importing bytes just for one call.
func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
