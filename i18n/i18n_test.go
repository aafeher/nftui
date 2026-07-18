package i18n

import (
	"testing"

	"golang.org/x/text/language"
)

// env builds a getenv stand-in from a map so Detect/Resolve can be driven
// without touching the real process environment.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDetect_Precedence(t *testing.T) {
	cases := []struct {
		name string
		vars map[string]string
		want language.Tag
	}{
		{"LC_ALL wins over LC_MESSAGES and LANG",
			map[string]string{"LC_ALL": "hu_HU.UTF-8", "LC_MESSAGES": "en_US.UTF-8", "LANG": "en_US.UTF-8"},
			language.Hungarian},
		{"LC_MESSAGES wins over LANG",
			map[string]string{"LC_MESSAGES": "hu_HU.UTF-8", "LANG": "en_US.UTF-8"},
			language.Hungarian},
		{"LANG used when it is the only one set",
			map[string]string{"LANG": "hu_HU.UTF-8"},
			language.Hungarian},
		{"nothing set falls back to English",
			map[string]string{},
			language.English},
		{"C locale is skipped, LANG decides",
			map[string]string{"LC_ALL": "C", "LANG": "hu_HU.UTF-8"},
			language.Hungarian},
		{"C.UTF-8 codeset form is skipped too",
			map[string]string{"LC_ALL": "C.UTF-8", "LANG": "hu_HU.UTF-8"},
			language.Hungarian},
		{"POSIX-only falls back to English",
			map[string]string{"LANG": "POSIX"},
			language.English},
		{"unsupported high-priority locale wins as English, no fall-through",
			map[string]string{"LC_ALL": "nl_NL.UTF-8", "LANG": "hu_HU.UTF-8"},
			language.English},
		{"@modifier and .codeset are stripped",
			map[string]string{"LANG": "hu_HU.UTF-8@euro"},
			language.Hungarian},
		{"bare language code works",
			map[string]string{"LANG": "hu"},
			language.Hungarian},
		{"any Spanish region matches the es catalog",
			map[string]string{"LANG": "es_MX.UTF-8"},
			language.Spanish},
		{"pt_BR matches the pt-BR catalog",
			map[string]string{"LANG": "pt_BR.UTF-8"},
			language.BrazilianPortuguese},
		{"European Portuguese nearest-matches pt-BR",
			map[string]string{"LANG": "pt_PT.UTF-8"},
			language.BrazilianPortuguese},
		{"any French region matches the fr catalog",
			map[string]string{"LANG": "fr_CA.UTF-8"},
			language.French},
		{"any German region matches the de catalog",
			map[string]string{"LANG": "de_AT.UTF-8"},
			language.German},
		{"any Italian region matches the it catalog",
			map[string]string{"LANG": "it_IT.UTF-8"},
			language.Italian},
		{"junk value is skipped, LANG decides",
			map[string]string{"LC_ALL": "!!!", "LANG": "hu"},
			language.Hungarian},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Detect(env(c.vars)); got != c.want {
				t.Errorf("Detect = %v, want %v", got, c.want)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	huEnv := env(map[string]string{"LANG": "hu_HU.UTF-8"})
	none := env(nil)

	cases := []struct {
		name   string
		flag   string
		getenv func(string) string
		want   language.Tag
	}{
		{"explicit --lang hu wins", "hu", none, language.Hungarian},
		{"explicit --lang en overrides LANG=hu", "en", huEnv, language.English},
		{"unsupported --lang falls to English, not the env", "nl", huEnv, language.English},
		{"a full locale is accepted as --lang", "hu_HU.UTF-8", none, language.Hungarian},
		{"explicit --lang es wins", "es", huEnv, language.Spanish},
		{"--lang pt-BR is accepted", "pt-BR", none, language.BrazilianPortuguese},
		{"--lang pt_BR POSIX spelling is accepted", "pt_BR", none, language.BrazilianPortuguese},
		{"bare --lang pt nearest-matches pt-BR", "pt", none, language.BrazilianPortuguese},
		{"explicit --lang fr wins", "fr", huEnv, language.French},
		{"explicit --lang de wins", "de", huEnv, language.German},
		{"explicit --lang it wins", "it", huEnv, language.Italian},
		{"empty --lang defers to detection", "", huEnv, language.Hungarian},
		{"whitespace --lang defers to detection", "   ", huEnv, language.Hungarian},
		{"empty --lang with no env is English", "", none, language.English},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Resolve(c.flag, c.getenv); got != c.want {
				t.Errorf("Resolve(%q) = %v, want %v", c.flag, got, c.want)
			}
		})
	}
}

func TestSetLanguageAndTranslate(t *testing.T) {
	t.Cleanup(func() { SetLanguage(English) })

	SetLanguage(English)
	if got := T("table.create.title"); got != "Create new table" {
		t.Errorf("en title = %q, want %q", got, "Create new table")
	}
	if Language() != language.English {
		t.Errorf("Language() = %v, want en", Language())
	}

	SetLanguage(language.Hungarian)
	if got := T("table.create.title"); got != "Új tábla létrehozása" {
		t.Errorf("hu title = %q, want %q", got, "Új tábla létrehozása")
	}
	if Language() != language.Hungarian {
		t.Errorf("Language() = %v, want hu", Language())
	}

	SetLanguage(language.Spanish)
	if got := T("table.create.title"); got != "Crear nueva tabla" {
		t.Errorf("es title = %q, want %q", got, "Crear nueva tabla")
	}

	SetLanguage(language.BrazilianPortuguese)
	if got := T("table.create.title"); got != "Criar nova tabela" {
		t.Errorf("pt-BR title = %q, want %q", got, "Criar nova tabela")
	}

	SetLanguage(language.French)
	if got := T("table.create.title"); got != "Créer une nouvelle table" {
		t.Errorf("fr title = %q, want %q", got, "Créer une nouvelle table")
	}

	SetLanguage(language.German)
	if got := T("table.create.title"); got != "Neue Tabelle erstellen" {
		t.Errorf("de title = %q, want %q", got, "Neue Tabelle erstellen")
	}

	SetLanguage(language.Italian)
	if got := T("table.create.title"); got != "Crea nuova tabella" {
		t.Errorf("it title = %q, want %q", got, "Crea nuova tabella")
	}

	// A region-qualified / unsupported tag matches the nearest supported one.
	SetLanguage(language.Dutch)
	if Language() != language.English {
		t.Errorf("unsupported tag: Language() = %v, want en fallback", Language())
	}
}

// The English catalog MUST reproduce the strings the code used to hold inline,
// byte-for-byte, so an English (default) build renders exactly as before and
// the existing golden-render tests stay green.
func TestEnglishCatalogByteIdentical(t *testing.T) {
	t.Cleanup(func() { SetLanguage(English) })
	SetLanguage(English)

	want := map[string]string{
		"table.create.title":        "Create new table",
		"table.create.family_label": "Family : ",
		"table.create.name_label":   "Name   : ",
	}
	for k, v := range want {
		if got := T(k); got != v {
			t.Errorf("T(%q) = %q, want %q (en must be byte-identical to the inline string)", k, got, v)
		}
	}
}

func TestTranslate_Fallbacks(t *testing.T) {
	t.Cleanup(func() {
		delete(catalogs[English], "__test_en_only__")
		SetLanguage(English)
	})

	// Missing everywhere → the key itself, never an empty string.
	SetLanguage(English)
	if got := T("no.such.key"); got != "no.such.key" {
		t.Errorf("missing key = %q, want the key itself", got)
	}

	// Present in en, absent from hu → English source (never blank).
	catalogs[English]["__test_en_only__"] = "English only"
	SetLanguage(language.Hungarian)
	if got := T("__test_en_only__"); got != "English only" {
		t.Errorf("en-fallback = %q, want %q", got, "English only")
	}
}

func TestTranslate_ArgFormatting(t *testing.T) {
	t.Cleanup(func() {
		delete(catalogs[English], "__test_fmt__")
		SetLanguage(English)
	})
	catalogs[English]["__test_fmt__"] = "saved %d rules to %s"
	SetLanguage(English)

	if got := T("__test_fmt__", 3, "out.conf"); got != "saved 3 rules to out.conf" {
		t.Errorf("formatted = %q, want %q", got, "saved 3 rules to out.conf")
	}
}

// Every English key must have a translation in every shipped catalog and vice
// versa — a missing or stray key is a catalog bug the moment it lands, not at
// render time.
func TestCatalogParity(t *testing.T) {
	en := catalogs[English]

	for _, tag := range supported {
		if tag == English {
			continue
		}
		other := catalogs[tag]
		for k := range en {
			if _, ok := other[k]; !ok {
				t.Errorf("%v catalog missing key %q that en defines", tag, k)
			}
		}
		for k := range other {
			if _, ok := en[k]; !ok {
				t.Errorf("%v catalog has key %q with no en source", tag, k)
			}
		}
	}
}
