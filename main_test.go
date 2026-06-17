package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nftui/ui"
)

// docFor must return the summary registered in flagDocs and panic on misses
// (a silent miss would strip the description from --help and the man page).
func TestDocFor(t *testing.T) {
	if got := docFor("table"); !strings.Contains(got, "restrict the tree") {
		t.Errorf("docFor(table) = %q, missing expected description", got)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Error("docFor must panic for an unregistered flag, got no panic")
		}
	}()
	_ = docFor("not-a-real-flag")
}

// writeUsage must render every registered flag (with its placeholder) and
// the synthetic --help entry, plus the usage block. We assert structural
// landmarks rather than exact byte-for-byte text so cosmetic tweaks don't
// break the test.
func TestWriteUsage(t *testing.T) {
	var buf bytes.Buffer
	writeUsage(&buf, "nftui")
	out := buf.String()

	for _, want := range []string{
		"Usage:",
		"Flags:",
		"--help",                       // synthetic entry must show up
		"sudo setcap cap_net_admin=ep", // capability hint always present
		"Examples:",
		"nftui [flags]", // the bin name was substituted in
	} {
		if !strings.Contains(out, want) {
			t.Errorf("writeUsage output missing %q\n--- output ---\n%s", want, out)
		}
	}

	// Every flag in flagDocs must appear with both its placeholder (if any)
	// and its summary — guards against the kind of drift the registry was
	// built to prevent.
	for _, f := range flagDocs {
		if !strings.Contains(out, "--"+f.name) {
			t.Errorf("flag %q missing from usage", f.name)
		}
		if f.arg != "" && !strings.Contains(out, f.arg) {
			t.Errorf("flag %q placeholder %q missing from usage", f.name, f.arg)
		}
		if !strings.Contains(out, f.summary) {
			t.Errorf("flag %q summary missing from usage", f.name)
		}
	}
}

// loadConfigFromFlag must reject a nonexistent path before touching nft, so
// the user gets a clear file-level error instead of a confusing nft binary
// failure. The nft path itself isn't unit-testable (it shells out and needs
// CAP_NET_ADMIN), so we only cover the validation gate here.
func TestLoadConfigFromFlag_RejectsMissingFile(t *testing.T) {
	err := loadConfigFromFlag(filepath.Join(t.TempDir(), "does-not-exist.conf"))
	if err == nil {
		t.Fatal("expected error for nonexistent path, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "--config:") {
		t.Errorf("error missing --config prefix: %q", msg)
	}
	if !strings.Contains(msg, "cannot read file") {
		t.Errorf("error missing file-level reason: %q", msg)
	}
}

// An empty path is the no-flag case: applyStartupOptions skips loadConfig
// entirely, so any call here is the user explicitly passing --config "".
// Treat it the same as a missing file rather than silently no-op'ing.
func TestLoadConfigFromFlag_RejectsEmptyPath(t *testing.T) {
	if err := loadConfigFromFlag(""); err == nil {
		t.Error("expected error for empty path, got nil")
	}
}

// A readable path that nft will reject must still pass the file-existence
// gate — the nft binary call is what produces the eventual error. Here we
// only verify that an *existing* file gets past os.Stat (the nft invocation
// itself is expected to fail in the sandbox, but with an nft-level message,
// not a file-level one).
func TestLoadConfigFromFlag_ExistingFileReachesNft(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.conf")
	if err := os.WriteFile(path, []byte("# empty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := loadConfigFromFlag(path)
	if err == nil {
		// On a privileged host with nft installed and the file is valid,
		// the call could succeed — that's fine, we only assert that no
		// "cannot read file" error fires.
		return
	}
	if strings.Contains(err.Error(), "cannot read file") {
		t.Errorf("existing file was treated as missing: %q", err)
	}
}

// applyStartupOptions with no flags set is a pure no-op: neither --config nor
// --table fires, so it returns nil without touching the kernel.
func TestApplyStartupOptions_Empty(t *testing.T) {
	if err := applyStartupOptions(ui.Options{}); err != nil {
		t.Errorf("empty options = %v, want nil", err)
	}
}

// A --config pointing at a missing file fails the existence gate before the
// (kernel-touching) --table validation runs, so the error is the file-level
// one from loadConfigFromFlag.
func TestApplyStartupOptions_BadConfig(t *testing.T) {
	err := applyStartupOptions(ui.Options{ConfigFile: filepath.Join(t.TempDir(), "nope.conf")})
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
	if !strings.Contains(err.Error(), "--config:") {
		t.Errorf("error = %q, want --config prefix", err)
	}
}

// With no --config, a --table filter is validated against the live kernel.
// Unprivileged, ListTables errors (EPERM → permission advice); as root the
// synthetic name simply isn't found. Either way a nonexistent table must
// surface a non-nil error — this drives applyStartupOptions' table branch and
// validateTableFilter.
func TestApplyStartupOptions_TableFilterValidates(t *testing.T) {
	if err := applyStartupOptions(ui.Options{TableFilter: "__nftui_no_such_table__"}); err == nil {
		t.Error("expected error for nonexistent table filter")
	}
}

func TestValidateTableFilter_Nonexistent(t *testing.T) {
	err := validateTableFilter("__nftui_no_such_table__")
	if err == nil {
		t.Fatal("expected error for nonexistent table")
	}
	// The message must name the table and either advise on permissions or
	// report it as not found — never an opaque bare error.
	msg := err.Error()
	if !strings.Contains(msg, "__nftui_no_such_table__") &&
		!strings.Contains(msg, "Permission denied") &&
		!strings.Contains(msg, "cannot read nftables tables") {
		t.Errorf("uninformative error: %q", msg)
	}
}
