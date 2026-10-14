package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// By default encrypt deletes the unencrypted file and decrypt deletes the
// encrypted file, so only one side of a pair exists at a time.
func TestEncryptDeletesPlaintextByDefault(t *testing.T) {
	p := newProject(t)
	p.init()
	p.write("config.unencrypted.json", `{"db":{"url":"postgres://u:OneFileSecret@h/db","pool":5}}`)
	r := p.expect(0, "encrypt")
	if p.exists("config.unencrypted.json") {
		t.Fatalf("encrypt must delete the unencrypted file by default\n%s", r)
	}
	if !p.exists("config.encrypted.json") {
		t.Fatal("encrypted file missing after encrypt")
	}
	if !strings.Contains(r.stdout, "--keep-both") {
		t.Fatalf("encrypt should mention --keep-both when it deletes\n%s", r)
	}
	// Injection still works from the encrypted file alone.
	if got := p.revealConfig(); !strings.Contains(got, "OneFileSecret") {
		t.Fatalf("JUREUMA_CONFIG = %s", got)
	}
}

func TestDecryptDeletesEncryptedAndEncryptRestoresKey(t *testing.T) {
	p := newProject(t)
	p.init()
	p.write("config.unencrypted.json", `{"a":"first-value","b":"second-value"}`)
	p.expect(0, "encrypt")
	before := p.read("config.encrypted.json")
	keyID, _ := p.privateKey()

	r := p.expect(0, "decrypt", "--dangerously-bypass-protections")
	if p.exists("config.encrypted.json") {
		t.Fatalf("decrypt must delete the encrypted file by default\n%s", r)
	}
	if !p.exists("config.unencrypted.json") {
		t.Fatal("unencrypted file missing after decrypt")
	}
	saved, _ := filepath.Glob(filepath.Join(p.jhome(), "state", "stash", "*.encrypted.json"))
	if len(saved) != 1 {
		t.Fatalf("decrypt must save one copy of the encrypted file, found %d", len(saved))
	}
	if data, _ := os.ReadFile(saved[0]); strings.Contains(string(data), "first-value") {
		t.Fatal("the saved copy must hold ciphertext only")
	}

	// Change one value; encrypt recreates the file with the same key and
	// reuses the unchanged ciphertext.
	p.write("config.unencrypted.json", `{"a":"first-value","b":"changed-value"}`)
	p.expect(0, "encrypt")
	after := p.read("config.encrypted.json")
	if !strings.Contains(after, keyID) {
		t.Fatalf("encrypt must reuse key %s\n%s", keyID, after)
	}
	if ctA := ciphertextOf(t, before, `"a"`); ctA == "" || !strings.Contains(after, ctA) {
		t.Fatal("unchanged value /a must keep its ciphertext")
	}
	if p.exists("config.unencrypted.json") {
		t.Fatal("encrypt must delete the unencrypted file")
	}
	if left, _ := filepath.Glob(filepath.Join(p.jhome(), "state", "stash", "*")); len(left) != 0 {
		t.Fatalf("the saved copy must be removed once the encrypted file exists again: %v", left)
	}
}

func TestEncryptFallsBackToGitHead(t *testing.T) {
	p := newProject(t)
	p.init()
	p.write("config.unencrypted.json", `{"a":"committed-value"}`)
	p.expect(0, "encrypt", "--keep-both")
	keyID, _ := p.privateKey()
	p.git("add", "config.encrypted.json")
	p.git("commit", "-q", "-m", "config")
	p.remove("config.encrypted.json")
	p.expect(0, "encrypt")
	if got := p.read("config.encrypted.json"); !strings.Contains(got, keyID) {
		t.Fatalf("encrypt must recover the key from git HEAD\n%s", got)
	}
}

func TestKeepBothKeepsBothFiles(t *testing.T) {
	p := newProject(t)
	p.init()
	p.write("config.unencrypted.json", `{"a":"x-value"}`)
	p.expect(0, "encrypt", "--keep-both")
	p.expect(0, "decrypt", "--keep-both", "--dangerously-bypass-protections")
	if !p.exists("config.unencrypted.json") || !p.exists("config.encrypted.json") {
		t.Fatal("--keep-both must keep both files")
	}
}

// ciphertextOf returns the ciphertext string of the first member named key.
func ciphertextOf(t *testing.T, encrypted, key string) string {
	t.Helper()
	i := strings.Index(encrypted, key+": \"jureuma:")
	if i < 0 {
		return ""
	}
	rest := encrypted[i+len(key)+3:]
	return rest[:strings.IndexByte(rest, '"')]
}
