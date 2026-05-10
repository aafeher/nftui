package nftexpr

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func FormatBitwise(bitwise *expr.Bitwise) string {
	return fmt.Sprintf("bitwise TBD")
}

func SerializeBitwise(b *expr.Bitwise) string {
	// Bitwise operations: AND, OR, XOR
	mask := formatData(b.Mask)
	xor := formatData(b.Xor)

	return fmt.Sprintf("& %s ^ %s", mask, xor)
}

func BitwiseToHumanReadable(b *expr.Bitwise, regMap map[uint32]string) string {
	srcContent := regMap[b.SourceRegister]
	if srcContent == "" {
		srcContent = fmt.Sprintf("register_%d", b.SourceRegister)
	}

	// Special handling for CT state
	if srcContent == string(CtKeyState) {
		// Try to decode mask to human language (pl. 8 -> new)
		decoded := DecodeCTValue(expr.CtKeySTATE, b.Mask)

		// If Xor is all zeros (which is the case with default masking),
		// then we can simply return the name.
		isXorZero := true
		for _, v := range b.Xor {
			if v != 0 {
				isXorZero = false
				break
			}
		}

		if isXorZero {
			return fmt.Sprintf("%s %v", srcContent, decoded)
		}
	}

	return fmt.Sprintf("%s & 0x%x ^ 0x%x", srcContent, b.Mask, b.Xor)
}
