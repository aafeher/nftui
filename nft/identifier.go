package nft

import (
	"fmt"
	"regexp"
)

// nftIdentifierMax is the usable length of an nftables table/chain/set name.
// The kernel stores names in a fixed NFT_NAME_MAXLEN (256) byte buffer
// including the NUL terminator, so 255 bytes are usable.
const nftIdentifierMax = 255

// nftIdentifierRe is the allowlist for unquoted nftables identifiers used as
// table / chain / set names: a leading letter followed by letters, digits,
// underscore, dot or hyphen. It deliberately excludes everything that could
// break out of an identifier's context in an `nft -f` script — whitespace,
// '{', '}', ';', '#', quotes, backslash, slash and newlines — which is how
// RenameTable / recreateBaseChain build the scripts they pipe into `nft -f -`.
var nftIdentifierRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)

// ValidateIdentifier reports whether name is a safe nftables identifier for a
// table, chain or set. It is the single defense-in-depth gate the TUI dialogs
// call before a user-supplied name reaches the kernel or an nft script
// (audit E-2 / S1: without it, a name containing nft-script metacharacters
// could inject statements into the privileged `nft -f -` transaction or
// silently corrupt the ruleset). Returns a user-facing error on violation.
func ValidateIdentifier(name string) error {
	if name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if len(name) > nftIdentifierMax {
		return fmt.Errorf("name is too long (%d chars; max %d)", len(name), nftIdentifierMax)
	}
	if !nftIdentifierRe.MatchString(name) {
		return fmt.Errorf("name must start with a letter and contain only letters, digits, '_', '.', '-'")
	}
	return nil
}
