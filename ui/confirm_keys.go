package ui

import (
	"golang.org/x/text/language"

	"nftui/i18n"
)

// confirmYesJ reports whether key is the German "[J]a" yes-mnemonic while
// German is the active language. Unlike the i/s/o aliases (hu [I]gen,
// es [S]í / pt [S]im, fr [O]ui), which are accepted in every language, "j"
// is language-gated: it is vim-down scroll muscle memory, so in any other
// language a stray "j" inside a confirm modal must stay inert instead of
// confirming a delete.
func confirmYesJ(key string) bool {
	return (key == "j" || key == "J") && i18n.Language() == language.German
}
