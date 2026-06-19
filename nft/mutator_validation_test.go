package nft

import (
	"runtime"
	"strings"
	"testing"

	"github.com/google/nftables"
)

// These tests assert the E-12 defense-in-depth guard: the name-taking mutators
// reject an unsafe identifier (one carrying nft-script metacharacters) BEFORE
// touching the kernel or building an `nft -f -` script — so the guard fires
// even for a future caller that bypasses the validated UI dialogs. Because the
// rejection happens first, these run without root: a valid name would proceed
// to netlink and need CAP_NET_ADMIN, but an invalid one never gets there.
//
// The mutators live in nft_linux.go; on non-Linux the stub returns a generic
// "only available on Linux" error with no validation, so the message assertion
// is Linux-only.

// badIdentMsg is the substring ValidateIdentifier returns for a name with
// disallowed characters; seeing it proves the guard fired (a netlink / exec
// failure would carry a different message).
const badIdentMsg = "letters, digits"

// injectionName carries a space and a ';' — exactly what must never reach the
// privileged `nft -f -` transaction.
const injectionName = "x; flush ruleset"

func skipIfNotLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("nft mutators are implemented only on Linux")
	}
}

func assertRejected(t *testing.T, op string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s accepted an injection identifier; want a validation error", op)
	}
	if !strings.Contains(err.Error(), badIdentMsg) {
		t.Fatalf("%s error = %q; want it to come from ValidateIdentifier (contain %q)", op, err, badIdentMsg)
	}
}

func TestCreateTable_RejectsUnsafeName(t *testing.T) {
	skipIfNotLinux(t)
	assertRejected(t, "CreateTable", CreateTable(nftables.TableFamilyINet, injectionName))
}

func TestCreateTable_RejectsEmptyName(t *testing.T) {
	skipIfNotLinux(t)
	if err := CreateTable(nftables.TableFamilyINet, ""); err == nil {
		t.Fatal("CreateTable accepted an empty name")
	}
}

func TestRenameTable_RejectsUnsafeNewName(t *testing.T) {
	skipIfNotLinux(t)
	tbl := &nftables.Table{Name: "validold", Family: nftables.TableFamilyINet}
	assertRejected(t, "RenameTable", RenameTable(tbl, injectionName))
}

func TestCreateChain_RejectsUnsafeName(t *testing.T) {
	skipIfNotLinux(t)
	tbl := &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}
	assertRejected(t, "CreateChain", CreateChain(tbl, &nftables.Chain{Name: injectionName}))
}

func TestUpdateChain_RejectsUnsafeName(t *testing.T) {
	skipIfNotLinux(t)
	old := &nftables.Chain{Name: "validold", Table: &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}}
	assertRejected(t, "UpdateChain", UpdateChain(old, &nftables.Chain{Name: injectionName}))
}

func TestCreateSet_RejectsUnsafeName(t *testing.T) {
	skipIfNotLinux(t)
	tbl := &nftables.Table{Name: "t", Family: nftables.TableFamilyINet}
	assertRejected(t, "CreateSet", CreateSet(tbl, CreateSetSpec{Name: injectionName}))
}
