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
		"--version",                    // synthetic entry must show up
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

// manPageFor maps a shipped locale tag to its nftui(1) page. English is the
// source page at man/nftui.1; every other language lives in man/<dir>/, the
// directory following man(1)'s convention of an underscore before the
// territory (pt-BR -> pt_BR).
func manPageFor(tag string) string {
	if tag == "en" {
		return filepath.Join("man", "nftui.1")
	}
	return filepath.Join("man", strings.ReplaceAll(tag, "-", "_"), "nftui.1")
}

// isFlagByte reports whether b can continue a flag name, so a mention of
// --table inside a hypothetical --tables isn't mistaken for the shorter flag.
func isFlagByte(b byte) bool {
	return b == '-' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// manFlagLines returns every line of a man page that names flag as a flag.
// Lines, not sections: the .SH headings are themselves translated (OPTIONS /
// OPZIONI / OPTIONEN / OPCIONES / …), so there is no language-independent
// section name to scope the search to, while the groff line that introduces a
// flag has the same shape in every language.
func manFlagLines(text, flag string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		for i := 0; ; {
			j := strings.Index(line[i:], flag)
			if j < 0 {
				break
			}
			end := i + j + len(flag)
			i = end
			if end < len(line) && isFlagByte(line[end]) {
				continue // only the prefix of a longer flag
			}
			out = append(out, line)
			break
		}
	}
	return out
}

// Every flag in flagDocs must be documented in every nftui(1) page the project
// ships, not only in --help. writeUsage is guarded by TestWriteUsage, but the
// man pages are hand-written — one per language — and no other test reads
// them, so a newly registered flag can silently miss all of them at once. The
// page set is derived from the embedded i18n catalogs, so a language that
// ships a catalog without its man page fails here too.
//
// The value placeholder is checked structurally rather than by name: the man
// pages translate it (\fIname\fR becomes \fInév\fR / \fInombre\fR / \fIName\fR),
// so the assertion is that a flag taking a value is introduced with *some*
// groff italic argument — not that it repeats flagDocs' English word.
func TestManPagesDocumentEveryFlag(t *testing.T) {
	catalogs, err := filepath.Glob(filepath.Join("i18n", "locales", "*.json"))
	if err != nil {
		t.Fatalf("globbing i18n catalogs: %v", err)
	}
	if len(catalogs) == 0 {
		t.Fatal("no i18n catalogs found — the locale layout moved and this test is blind")
	}

	for _, catalog := range catalogs {
		tag := strings.TrimSuffix(filepath.Base(catalog), ".json")
		page := manPageFor(tag)

		raw, err := os.ReadFile(page)
		if err != nil {
			t.Errorf("locale %q ships a catalog but no man page: %v", tag, err)
			continue
		}
		// groff escapes every hyphen as `\-`, so --read-only is written
		// `\-\-read\-only`. Unescape once so the flags match as spelled.
		text := strings.ReplaceAll(string(raw), `\-`, "-")

		for _, f := range flagDocs {
			lines := manFlagLines(text, "--"+f.name)
			if len(lines) == 0 {
				t.Errorf("%s: flag --%s is not documented", page, f.name)
				continue
			}
			if f.arg == "" {
				continue
			}
			documented := false
			for _, line := range lines {
				at := strings.Index(line, "--"+f.name)
				if italic := strings.Index(line, `\fI`); italic > at {
					documented = true
					break
				}
			}
			if !documented {
				t.Errorf("%s: flag --%s takes %s but is documented without a value placeholder",
					page, f.name, f.arg)
			}
		}
	}
}

// resolveVersion prefers the ldflags-injected version; falls back to the Go
// build-info module version (set for `go install module@vX.Y.Z`); and finally
// to "dev" for a plain `go build` / `(devel)` checkout where neither is set.
func TestResolveVersion(t *testing.T) {
	cases := []struct {
		name, injected, build, want string
	}{
		{"injected wins", "0.9.0", "v1.2.3", "0.9.0"},
		{"injected wins over empty build", "0.9.0", "", "0.9.0"},
		{"build info used when not injected", "", "v1.2.3", "v1.2.3"},
		{"devel build falls back to dev", "", "(devel)", "dev"},
		{"empty everything falls back to dev", "", "", "dev"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveVersion(c.injected, c.build); got != c.want {
				t.Errorf("resolveVersion(%q, %q) = %q, want %q", c.injected, c.build, got, c.want)
			}
		})
	}
}

// writeVersion renders a single "<bin> <version>" line so `nftui --version`
// output is stable and machine-greppable.
func TestWriteVersion(t *testing.T) {
	var buf bytes.Buffer
	writeVersion(&buf, "nftui", "0.9.0")
	out := buf.String()
	if !strings.Contains(out, "nftui") || !strings.Contains(out, "0.9.0") {
		t.Errorf("writeVersion output = %q, want bin name + version", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("writeVersion must end with a newline: %q", out)
	}
	if n := strings.Count(out, "\n"); n != 1 {
		t.Errorf("writeVersion must be a single line, got %d newlines: %q", n, out)
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
