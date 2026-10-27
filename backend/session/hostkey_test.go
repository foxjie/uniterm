package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// withTempKnownHosts redirects KnownHostsPath at a temp file for the test by
// pointing $HOME at a temp dir. Returns the expected known_hosts path and a
// restore func. The temp dir is created fresh (no known_hosts file yet).
func withTempKnownHosts(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".uniterm"), 0700); err != nil {
		t.Fatalf("mkdir .uniterm: %v", err)
	}
	prevHome, hadHome := os.LookupEnv("HOME")
	if err := os.Setenv("HOME", dir); err != nil {
		t.Fatalf("setenv HOME: %v", err)
	}
	path := filepath.Join(dir, ".uniterm", "known_hosts")
	return path, func() {
		if hadHome {
			_ = os.Setenv("HOME", prevHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	}
}

// generateTestHostKey generates a fresh ed25519 SSH key pair for testing
// host-key verification. Returns the PublicKey (for the callback) and its
// base64 wire-format encoding (for known_hosts comparison).
func generateTestHostKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	_ = pub // ed25519 pub is derivable from priv; signer.PublicKey is canonical
	sshPub := signer.PublicKey()
	return sshPub, base64.StdEncoding.EncodeToString(sshPub.Marshal())
}

// makeAlternateKey returns a second, distinct PublicKey to simulate a
// changed server key.
func makeAlternateKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	return generateTestHostKey(t)
}

func TestParseHostKeyStrategy(t *testing.T) {
	cases := []struct {
		in   string
		want HostKeyStrategy
	}{
		{"", HostKeyAcceptNew},
		{"accept-new", HostKeyAcceptNew},
		{"ACCEPT-NEW", HostKeyAcceptNew},
		{"strict", HostKeyStrict},
		{"Strict", HostKeyStrict},
		{"off", HostKeyOff},
		{"insecure", HostKeyOff},
		{"disable", HostKeyOff},
		{"unknown", HostKeyAcceptNew}, // unknown → default
	}
	for _, c := range cases {
		if got := ParseHostKeyStrategy(c.in); got != c.want {
			t.Errorf("ParseHostKeyStrategy(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestHostKeyStrategyString(t *testing.T) {
	if HostKeyAcceptNew.String() != "accept-new" {
		t.Errorf("AcceptNew.String() = %q, want accept-new", HostKeyAcceptNew.String())
	}
	if HostKeyStrict.String() != "strict" {
		t.Errorf("Strict.String() = %q, want strict", HostKeyStrict.String())
	}
	if HostKeyOff.String() != "off" {
		t.Errorf("Off.String() = %q, want off", HostKeyOff.String())
	}
}

func TestHostKeyCallback_OffIsInsecure(t *testing.T) {
	// HostKeyOff must accept any key (legacy behaviour).
	cb := HostKeyCallback("h", "22", HostKeyOff)
	key, _ := generateTestHostKey(t)
	if err := cb("h", nil, key); err != nil {
		t.Errorf("Off strategy rejected key: %v", err)
	}
}

func TestHostKeyCallback_TOFUFirstConnectRecords(t *testing.T) {
	path, restore := withTempKnownHosts(t)
	defer restore()

	key, keyB64 := generateTestHostKey(t)
	cb := HostKeyCallback("example.com", "22", HostKeyAcceptNew)
	if err := cb("example.com", nil, key); err != nil {
		t.Fatalf("first connect should pass (TOFU), got: %v", err)
	}
	// known_hosts should now contain a line for example.com.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	wantLine := "example.com " + key.Type() + " " + keyB64
	if !strings.Contains(string(data), wantLine) {
		t.Errorf("known@known_hosts missing expected line\nwant: %s\nhave: %s", wantLine, data)
	}
}

func TestHostKeyCallback_MatchingKeyPasses(t *testing.T) {
	_, restore := withTempKnownHosts(t)
	defer restore()

	key, _ := generateTestHostKey(t)
	cb := HostKeyCallback("example.com", "22", HostKeyAcceptNew)
	if err := cb("example.com", nil, key); err != nil {
		t.Fatalf("first connect: %v", err)
	}
	// Second connect with the same key must pass.
	if err := cb("example.com", nil, key); err != nil {
		t.Errorf("second connect with same key should pass, got: %v", err)
	}
}

func TestHostKeyCallback_ChangedKeyReturnsError(t *testing.T) {
	_, restore := withTempKnownHosts(t)
	defer restore()

	key1, _ := generateTestHostKey(t)
	cb := HostKeyCallback("example.com", "22", HostKeyAcceptNew)
	if err := cb("example.com", nil, key1); err != nil {
		t.Fatalf("first connect: %v", err)
	}

	key2, _ := makeAlternateKey(t)
	if key2 == nil {
		t.Skip("alternate key unavailable")
	}
	err := cb("example.com", nil, key2)
	if err == nil {
		t.Fatalf("changed key should return error, got nil")
	}
	changed, ok := AsHostKeyChangedError(err)
	if !ok {
		t.Fatalf("error should be *HostKeyChangedError, got %T: %v", err, err)
	}
	if changed.Host != "example.com" {
		t.Errorf("changed.Host = %q, want example.com", changed.Host)
	}
	if changed.NewFp == "" || changed.OldFp == "" {
		t.Errorf("fingerprints should be non-empty: old=%q new=%q", changed.OldFp, changed.NewFp)
	}
	if changed.OldFp == changed.NewFp {
		t.Errorf("old and new fingerprints should differ")
	}
}

func TestHostKeyCallback_StrictRejectsChangeWithoutEmit(t *testing.T) {
	_, restore := withTempKnownHosts(t)
	defer restore()

	// Install a sentinel emitter that fails the test if invoked.
	emitted := false
	SetHostKeyEmitter(func(name string, payload any) {
		emitted = true
	})
	defer SetHostKeyEmitter(nil)

	key1, _ := generateTestHostKey(t)
	cb := HostKeyCallback("example.com", "22", HostKeyStrict)
	if err := cb("example.com", nil, key1); err != nil {
		t.Fatalf("first connect (strict): %v", err)
	}

	key2, _ := makeAlternateKey(t)
	if key2 == nil {
		t.Skip("alternate key unavailable")
	}
	err := cb("example.com", nil, key2)
	if err == nil {
		t.Fatalf("strict should reject changed key")
	}
	if emitted {
		t.Errorf("strict strategy must not emit frontend event")
	}
}

func TestHostKeyCallback_AcceptNewEmitsEvent(t *testing.T) {
	_, restore := withTempKnownHosts(t)
	defer restore()

	emitted := false
	var emittedName string
	SetHostKeyEmitter(func(name string, payload any) {
		emitted = true
		emittedName = name
	})
	defer SetHostKeyEmitter(nil)

	key1, _ := generateTestHostKey(t)
	cb := HostKeyCallback("example.com", "2222", HostKeyAcceptNew)
	if err := cb("example.com", nil, key1); err != nil {
		t.Fatalf("first connect: %v", err)
	}

	key2, _ := makeAlternateKey(t)
	if key2 == nil {
		t.Skip("alternate key unavailable")
	}
	_ = cb("example.com", nil, key2) // returns error, but we care about the event
	if !emitted {
		t.Errorf("AcceptNew should emit session:hostkey-changed event")
	}
	if emittedName != "session:hostkey-changed" {
		t.Errorf("emitted event name = %q, want session:hostkey-changed", emittedName)
	}
}

func TestAcceptHostKeyChange_UpdatesKnownHosts(t *testing.T) {
	_, restore := withTempKnownHosts(t)
	defer restore()

	key1, _ := generateTestHostKey(t)
	cb := HostKeyCallback("example.com", "22", HostKeyAcceptNew)
	if err := cb("example.com", nil, key1); err != nil {
		t.Fatalf("first connect: %v", err)
	}

	key2, key2B64 := makeAlternateKey(t)
	if key2 == nil {
		t.Skip("alternate key unavailable")
	}
	// User accepts the new key via the frontend dialog.
	if err := AcceptHostKeyChange("example.com", "22", key2.Type(), key2B64); err != nil {
		t.Fatalf("AcceptHostKeyChange: %v", err)
	}
	// Now connecting with key2 should pass.
	if err := cb("example.com", nil, key2); err != nil {
		t.Errorf("after accept, connect with new key should pass, got: %v", err)
	}
	// And key1 should now be the one that triggers a change.
	if err := cb("example.com", nil, key1); err == nil {
		t.Errorf("after accept, old key should now be rejected")
	}
}

func TestKnownHostsKey_PortFormatting(t *testing.T) {
	if got := knownHostsKey("h", "22"); got != "h" {
		t.Errorf("port 22 should drop bracket notation: got %q", got)
	}
	if got := knownHostsKey("h", ""); got != "h" {
		t.Errorf("empty port should drop bracket notation: got %q", got)
	}
	if got := knownHostsKey("h", "2222"); got != "[h]:2222" {
		t.Errorf("non-22 port should use [host]:port: got %q", got)
	}
}

func TestResolveHostKeyStrategy_ConfigOverridesDefault(t *testing.T) {
	prev := GetDefaultHostKeyStrategy()
	defer SetDefaultHostKeyStrategy(prev)

	SetDefaultHostKeyStrategy(HostKeyStrict)
	if got := ResolveHostKeyStrategy(""); got != HostKeyStrict {
		t.Errorf("empty config should use default strict, got %v", got)
	}
	if got := ResolveHostKeyStrategy("off"); got != HostKeyOff {
		t.Errorf("config off should override default, got %v", got)
	}
	if got := ResolveHostKeyStrategy("accept-new"); got != HostKeyAcceptNew {
		t.Errorf("config accept-new should override default, got %v", got)
	}
}
