package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
