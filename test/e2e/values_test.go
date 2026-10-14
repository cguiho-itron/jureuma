package e2e

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CGuiho/jureuma/internal/crypt"
)

func TestSetTypingAndPaths(t *testing.T) {
	needSh(t)
	p := newProject(t)
	p.init()

	p.expect(0, "set", "/s", "123")
	p.expect(0, "set", "/n", "--json", "123")
	p.expect(0, "set", "/f", "--json", "1.50")
	p.expect(0, "set", "/b", "--json", "true")
	p.expect(0, "set", "/z", "--json", "null")
	p.expectStdin(0, "from-stdin-value\n", "set", "/stdin", "--value-stdin")
	p.write("value.txt", "from-file-value\n")
	p.expect(0, "set", "/file", "--value-file", "value.txt")
	p.expect(0, "set", "/obj", "--json", `{"host":"h","port":5432}`)
	p.expect(0, "set", "/a/b/c", "deep")
	p.expect(0, "set", "/arr", "--json", "[1]")
	p.expect(0, "set", "/arr/1", "--json", "2")
	p.expect(0, "set", "/arr/-", "--json", "3")
	p.expect(0, "set", "/arr/0", "--json", "0")
	p.expect(0, "set", "/a~1b", "slash-key")

	want := `{"s":"123","n":123,"f":1.50,"b":true,"z":null,"stdin":"from-stdin-value","file":"from-file-value","obj":{"host":"h","port":5432},"a":{"b":{"c":"deep"}},"arr":[0,2,3],"a/b":"slash-key"}`
	if got := p.revealConfig(); got != want {
		t.Fatalf("document after sets:\n got %s\nwant %s", got, want)
	}
	// Objects given with --json are expanded into per-leaf ciphertexts.
	var enc map[string]any
	json.Unmarshal([]byte(p.read("config.encrypted.json")), &enc)
	obj, _ := enc["obj"].(map[string]any)
	if obj == nil || !crypt.IsCiphertext(obj["host"].(string)) || !crypt.IsCiphertext(obj["port"].(string)) {
		t.Fatalf("--json object not expanded per leaf: %v", enc["obj"])
	}
	// set mirrors into the existing .json plaintext file.
	if stripWS(p.read("config.unencrypted.json")) != stripWS(`{"s":"123","n":123,"f":1.50,"b":true,"z":null,"stdin":"from-stdin-value","file":"from-file-value","obj":{"host":"h","port":5432},"a":{"b":{"c":"deep"}},"arr":[0,2,3],"a/b":"slash-key"}`) {
		t.Fatalf("plaintext mirror differs:\n%s", p.read("config.unencrypted.json"))
	}

	before := p.read("config.encrypted.json")
	failures := [][]string{
		{"set", "/s/x", "through-a-leaf"},       // passes through a string leaf
		{"set", "/arr/0/x", "through-a-number"}, // passes through a number leaf
		{"set", "/arr/5", "--json", "9"},        // beyond len
		{"set", "/n", "--json", "{bad json"},    // invalid JSON
		{"set", "/$jureuma/x", "meta"},          // reserved
		{"set", "no-slash", "x"},                // not a pointer
		{"set", "/twice", "x", "--value-stdin"}, // two sources
		{"set", "/none"},                        // no value
	}
	for _, args := range failures {
		r := p.runStdin("y\n", args...)
		if r.code == 0 {
			t.Fatalf("expected failure\n%s", r)
		}
	}
	if p.read("config.encrypted.json") != before {
		t.Fatal("a failed set modified the encrypted file")
	}
	// The value is never echoed.
	r := p.expectStdin(0, "echo-check-value\n", "set", "/echo", "--value-stdin")
	assertNo(t, "set output", r.out(), "echo-check-value")
}

func TestSetNonStringAgainstSchemaNeedsJSON(t *testing.T) {
	p := newProject(t)
	p.setup(`{"port":8080,"name":"svc"}`)
	p.expect(0, "schema", "infer")
	r := p.run("set", "/port", "9090")
	if r.code != 4 || !strings.Contains(r.out(), "--json") {
		t.Fatalf("string for a number path: want exit 4 suggesting --json\n%s", r)
	}
	p.expect(0, "set", "/port", "--json", "9090")
	// Adding a property the inferred schema forbids is a validation failure.
	if r := p.run("set", "/extra", "x"); r.code != 4 {
		t.Fatalf("additionalProperties false: want exit 4\n%s", r)
	}
	p.expect(0, "set", "/extra", "x", "--allow-invalid")
	// Removing a required property needs --allow-invalid.
	if r := p.run("unset", "/name"); r.code != 4 {
		t.Fatalf("removing a required property: want exit 4\n%s", r)
	}
	p.expect(0, "unset", "/name", "--allow-invalid")
}

func TestUnsetRules(t *testing.T) {
	needSh(t)
	p := newProject(t)
	p.setup(`{"arr":["e0","e1","e2","e3"],"obj":{"k":"v","keep":{"x":1}},"top":"t"}`)

	restore := p.hideKeys()
	// Keyless: the last array element and object members are fine.
	p.expect(0, "unset", "/arr/3")
	p.expect(0, "unset", "/obj/keep/x")
	// A middle element needs the key (its tail must be re-encrypted).
	before := p.read("config.encrypted.json")
	r := p.run("unset", "/arr/0")
	if r.code != 5 {
		t.Fatalf("keyless unset of a middle element: want exit 5\n%s", r)
	}
	if p.read("config.encrypted.json") != before {
		t.Fatal("refused unset modified the encrypted file")
	}
	if r := p.run("unset", "/arr/-"); r.code != 2 {
		t.Fatalf("unset /arr/-: want exit 2\n%s", r)
	}
	if r := p.run("unset", "/missing"); r.code == 0 {
		t.Fatalf("unset of a missing path must fail\n%s", r)
	}
	restore()

	// With the key the tail is re-indexed and re-encrypted.
	p.expect(0, "unset", "/arr/0")
	if got := p.revealConfig(); got != `{"arr":["e1","e2"],"obj":{"k":"v","keep":{}},"top":"t"}` {
		t.Fatalf("after unsets: %s", got)
	}
	// Removing a container removes the subtree, the parent stays.
	p.expect(0, "unset", "/obj/keep")
	p.expect(0, "unset", "/obj/k")
	if got := p.revealConfig(); got != `{"arr":["e1","e2"],"obj":{},"top":"t"}` {
		t.Fatalf("after subtree unset: %s", got)
	}
	// unset is mirrored into the plaintext file.
	if stripWS(p.read("config.unencrypted.json")) != `{"arr":["e1","e2"],"obj":{},"top":"t"}` {
		t.Fatalf("plaintext mirror: %s", p.read("config.unencrypted.json"))
	}
	if o, _ := p.statusJSON(); o != "in-sync" {
		t.Fatalf("status after keyed unsets: %s", o)
	}
}

func TestStatusStates(t *testing.T) {
	p := newProject(t)
	p.setup(`{"a":"alpha-1","b":"bravo-1","c":"charlie-1"}`)
	if o, _ := p.statusJSON(); o != "in-sync" {
		t.Fatalf("fresh: %s", o)
	}

	// Human edit of the plaintext: unencrypted-newer.
	p.write("config.unencrypted.json", `{"a":"alpha-2","b":"bravo-1","c":"charlie-1"}`)
	o, st := p.statusJSON()
	if o != "unencrypted-newer" || st["/a"] != "unencrypted-newer" || st["/b"] != "in-sync" {
		t.Fatalf("after plaintext edit: %s %v", o, st)
	}

	// Keyless set on the encrypted side while the plaintext keeps its old /b:
	// encrypted-newer for /b; editing /a on both sides: conflict.
	plain := p.read("config.unencrypted.json")
	restore := p.hideKeys()
	p.expect(0, "set", "/b", "bravo-2")
	p.expect(0, "set", "/a", "alpha-3")
	o, st = p.statusJSON()
	if o != "key-unavailable" {
		t.Fatalf("without the key overall is %s", o)
	}
	meta := p.encMeta("config.encrypted.json")
	pending, _ := meta["pending"].([]any)
	if len(pending) != 2 {
		t.Fatalf("keyless sets must be pending: %v", meta["pending"])
	}
	restore()
	p.write("config.unencrypted.json", plain)
	o, st = p.statusJSON()
	if st["/b"] != "encrypted-newer" || st["/a"] != "conflict" || st["/c"] != "in-sync" || o != "conflict" {
		t.Fatalf("want /a conflict, /b encrypted-newer, overall conflict; got %s %v", o, st)
	}
	// status is read-only.
	enc := p.read("config.encrypted.json")
	p.expect(0, "status")
	if p.read("config.encrypted.json") != enc || p.read("config.unencrypted.json") != plain {
		t.Fatal("status modified a file")
	}
	// encrypt refuses to lose the agent's set; decrypt refuses to lose the human edit.
	if r := p.run("encrypt", "--keep-both"); r.code == 0 {
		t.Fatalf("encrypt over a conflict must refuse\n%s", r)
	}
	if r := p.run("decrypt", "--keep-both", "--dangerously-bypass-protections"); r.code == 0 {
		t.Fatalf("decrypt over unsaved edits must refuse\n%s", r)
	}
	if p.read("config.encrypted.json") != enc || p.read("config.unencrypted.json") != plain {
		t.Fatal("refused encrypt/decrypt modified a file")
	}
	// --force resolves the conflict on /a in favour of the plaintext, but
	// keeps the agent's keyless set of /b (encrypted-newer only) pending.
	r := p.expect(0, "encrypt", "--keep-both", "--force")
	if !strings.Contains(r.stderr, "/b") {
		t.Fatalf("encrypt --force must list the kept encrypted-side change\n%s", r)
	}
	o, st = p.statusJSON()
	if o != "encrypted-newer" || st["/a"] != "in-sync" || st["/b"] != "encrypted-newer" {
		t.Fatalf("after encrypt --force: %s %v", o, st)
	}
	if pending, _ := p.encMeta("config.encrypted.json")["pending"].([]any); len(pending) != 1 {
		t.Fatalf("encrypt --force must keep /b pending: %v", pending)
	}
	p.expect(0, "decrypt", "--keep-both", "--dangerously-bypass-protections")
	if o, _ := p.statusJSON(); o != "in-sync" {
		t.Fatalf("after decrypt: %s", o)
	}
	if pending, _ := p.encMeta("config.encrypted.json")["pending"].([]any); len(pending) != 0 {
		t.Fatalf("decrypt must clear pending: %v", pending)
	}

	// Missing plaintext.
	p.remove("config.unencrypted.json")
	if o, _ := p.statusJSON(); o != "unencrypted-missing" {
		t.Fatalf("without plaintext: %s", o)
	}
	// decrypt --force overrides unsaved edits.
	p.expect(0, "decrypt", "--keep-both", "--dangerously-bypass-protections")
	p.write("config.unencrypted.json", `{"a":"edited","b":"bravo-2","c":"charlie-1"}`)
	if r := p.run("decrypt", "--keep-both", "--dangerously-bypass-protections"); r.code == 0 {
		t.Fatalf("decrypt over an edit must refuse\n%s", r)
	}
	p.expect(0, "decrypt", "--keep-both", "--dangerously-bypass-protections", "--force")
	if o, _ := p.statusJSON(); o != "in-sync" {
		t.Fatalf("after decrypt --force: %s", o)
	}
}

func TestCheckFailures(t *testing.T) {
	p := newProject(t)
	p.setup(`{"svc":{"url":"check-value-url"}}`)
	p.expect(0, "schema", "infer")
	p.expect(0, "encrypt", "--keep-both")
	r := p.expect(0, "check")
	assertNo(t, "check", r.out(), "check-value-url")

	// Tracked plaintext.
	p.git("add", "-f", "config.unencrypted.json")
	r = p.run("check")
	if r.code != 1 || !strings.Contains(r.stdout, "tracked by git") {
		t.Fatalf("tracked plaintext: want exit 1\n%s", r)
	}
	p.git("rm", "-q", "--cached", "config.unencrypted.json")
	p.expect(0, "check")

	// Missing .gitignore block.
	gi := p.read(".gitignore")
	p.write(".gitignore", "*.unencrypted.json\n*.unencrypted.jsonc\n")
	if r := p.run("check"); r.code != 1 {
		t.Fatalf("missing gitignore block: want exit 1\n%s", r)
	}
	p.write(".gitignore", gi)

	// Swapped publicKey (recipient key replaced, keyId consistent) is detected
	// against git HEAD.
	p.git("add", ".gitignore", "config.encrypted.json", "config.schema.json", "jureuma.yaml")
	p.git("commit", "-q", "-m", "e2e")
	orig := p.read("config.encrypted.json")
	meta := p.encMeta("config.encrypted.json")
	otherSK, _ := crypt.GenerateKey()
	otherPK := otherSK.Public()
	swapped := strings.Replace(orig, meta["publicKey"].(string), otherPK.String(), 1)
	swapped = strings.Replace(swapped, `"keyId": "`+meta["keyId"].(string)+`"`, `"keyId": "`+crypt.KeyID(otherPK)+`"`, 1)
	p.write("config.encrypted.json", swapped)
	r = p.run("check")
	if !strings.Contains(r.stdout, "differs from the version at git HEAD") {
		t.Fatalf("swapped publicKey not reported\n%s", r)
	}
	if r := p.run("status"); !strings.Contains(r.stderr, "git HEAD") {
		t.Fatalf("status must warn about a swapped publicKey\n%s", r)
	}
	// Ciphertexts under a key that is not the file's key are reported.
	if !strings.Contains(r.stdout, meta["keyId"].(string)) {
		t.Fatalf("check must report values under another key\n%s", r)
	}

	// keyId that does not match publicKey: exit 5 everywhere the file is loaded.
	mismatch := strings.Replace(orig, `"keyId": "`+meta["keyId"].(string)+`"`, `"keyId": "`+crypt.KeyID(otherPK)+`"`, 1)
	p.write("config.encrypted.json", mismatch)
	for _, args := range [][]string{{"check"}, {"status"}, {"list"}, {"encrypt", "--keep-both"}, {"set", "/svc/url", "x"}} {
		if r := p.run(args...); r.code != 5 {
			t.Fatalf("keyId/publicKey mismatch: want exit 5\n%s", r)
		}
	}
	// A private key from the environment that is not the file's key.
	p.write("config.encrypted.json", orig)
	envName := "JUREUMA_PRIVATE_KEY_" + strings.ToUpper(meta["keyId"].(string))
	r = p.runEnv([]string{envName + "=" + otherSK.String()}, "check")
	if r.code != 5 {
		t.Fatalf("wrong private key in %s: want exit 5\n%s", envName, r)
	}
	assertNo(t, "key mismatch output", r.out(), otherSK.String(), strings.TrimPrefix(otherSK.String(), "jureuma-sk-1:"))
	p.expect(0, "check")
}
