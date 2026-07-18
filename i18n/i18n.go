// Package i18n provides startup-resolved, catalog-backed translation of
// nftui's user-facing strings.
//
// English is the source locale: every message key has an English value that
// reproduces the string the code used to hold inline, so an untranslated build
// renders exactly as before. Other languages layer on top via per-language JSON
// catalogs embedded at build time (locales/<tag>.json).
//
// The active language is resolved once at startup — an explicit --lang flag
// wins, otherwise the POSIX locale environment (LC_ALL > LC_MESSAGES > LANG),
// otherwise English — and does not change at runtime in this version. Call
// SetLanguage before the TUI renders; thereafter T(key) reads the resolved
// catalog with an English-then-key fallback so a missing entry is never blank.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/text/language"
)

//go:embed locales/*.json
var localeFS embed.FS

// English is the source locale and the fallback for every missing key.
var English = language.English

// supported lists every language nftui ships a catalog for, English first so it
// is the matcher's default. Adding a language is a two-line change: drop a
// locales/<tag>.json file and add its tag here.
var supported = []language.Tag{
	language.English,
	language.Hungarian,
	language.Spanish,
	language.BrazilianPortuguese,
	language.French,
	language.German,
	language.Italian,
}

var matcher = language.NewMatcher(supported)

// catalogs maps each supported language tag to its key→string table, loaded
// once from the embedded JSON by init.
var catalogs = map[language.Tag]map[string]string{}

// active is the resolved language's catalog and activeTag its tag; both default
// to English until SetLanguage runs. active is never nil after init.
var (
	active    map[string]string
	activeTag = English
)

func init() {
	loadCatalogs()
	active = catalogs[English]
}

// loadCatalogs reads every supported language's embedded JSON into catalogs. The
// files are compiled into the binary, so a missing or malformed catalog is a
// build-time programming error, not a runtime condition — panic rather than
// degrade silently and ship half a translation.
func loadCatalogs() {
	for _, tag := range supported {
		name := "locales/" + tag.String() + ".json"
		data, err := localeFS.ReadFile(name)
		if err != nil {
			panic("i18n: missing embedded catalog " + name + ": " + err.Error())
		}
		m := map[string]string{}
		if err := json.Unmarshal(data, &m); err != nil {
			panic("i18n: malformed catalog " + name + ": " + err.Error())
		}
		catalogs[tag] = m
	}
}

// parseLocale turns a POSIX locale value like "hu_HU.UTF-8@euro" into a BCP-47
// language tag, stripping the "@modifier" and ".codeset" suffixes POSIX allows
// but BCP-47 does not and normalising the "_" region separator to "-". The
// bool is false when the value carries no real language: the POSIX "C" /
// "POSIX" locales (in any codeset form, e.g. "C.UTF-8") and unparseable junk.
func parseLocale(raw string) (language.Tag, bool) {
	if i := strings.IndexByte(raw, '@'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '.'); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.ReplaceAll(raw, "_", "-")
	if raw == "" || raw == "C" || raw == "POSIX" {
		return language.Und, false
	}
	tag, err := language.Parse(raw)
	if err != nil {
		return language.Und, false
	}
	return tag, true
}

// Detect resolves the operating system's preferred language from the POSIX
// locale environment, honouring the precedence LC_ALL > LC_MESSAGES > LANG. The
// first variable that holds a parseable locale decides the result (matched to
// the nearest supported language, English if none matches) — a higher-priority
// variable being set to an *unsupported* language still wins as English rather
// than falling through to a lower-priority one, per POSIX. An unset / "C" /
// "POSIX" / unparseable value is skipped. getenv is injected so the precedence
// is unit-testable without touching the real process environment.
func Detect(getenv func(string) string) language.Tag {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		raw := strings.TrimSpace(getenv(key))
		if raw == "" {
			continue
		}
		tag, ok := parseLocale(raw)
		if !ok {
			continue
		}
		_, idx, _ := matcher.Match(tag)
		return supported[idx]
	}
	return English
}

// Resolve picks the effective language. An explicit flagVal (the --lang value)
// wins: if it names a supported language it is used, and if it is set but
// unsupported the result is English — the user asked for a specific language, so
// the source locale is a truer answer than second-guessing from the
// environment. An empty flagVal defers to Detect(getenv).
func Resolve(flagVal string, getenv func(string) string) language.Tag {
	if flagVal = strings.TrimSpace(flagVal); flagVal != "" {
		if tag, ok := parseLocale(flagVal); ok {
			if _, idx, conf := matcher.Match(tag); conf > language.No {
				return supported[idx]
			}
		}
		return English
	}
	return Detect(getenv)
}

// SetLanguage switches the active catalog to tag's language (matched to the
// nearest supported one; English if none matches). Call once at startup, before
// the TUI renders — the language does not change at runtime in this version.
func SetLanguage(tag language.Tag) {
	if c, ok := catalogs[tag]; ok {
		active, activeTag = c, tag
		return
	}
	if _, idx, conf := matcher.Match(tag); conf > language.No {
		active, activeTag = catalogs[supported[idx]], supported[idx]
		return
	}
	active, activeTag = catalogs[English], English
}

// Language returns the currently active language tag.
func Language() language.Tag { return activeTag }

// T translates key into the active language. A key missing from the active
// catalog falls back to the English catalog, then to the key string itself, so
// a gap surfaces as the English source or a visible key — never an empty
// string. When args are supplied the resolved value is run through fmt.Sprintf,
// so a catalog entry may carry %s/%d/… verbs.
func T(key string, args ...any) string {
	s, ok := active[key]
	if !ok {
		if s, ok = catalogs[English][key]; !ok {
			s = key
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}
