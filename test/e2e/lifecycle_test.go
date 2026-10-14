package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// snapshot hashes every regular file under root (skipping .git).
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if !d.Type().IsRegular() {
			return nil
		}
		// The update cache, locks and run registry are disposable state.
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.Contains(rel, "/locks/") || strings.Contains(rel, "/run/") || strings.HasSuffix(rel, "cache.json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func diffSnapshots(a, b map[string]string) []string {
	var d []string
	for k, v := range a {
		if b[k] != v {
			d = append(d, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			d = append(d, k+" (new)")
		}
	}
	sort.Strings(d)
	return d
}

func TestInitCreatesPairAndIsIdempotent(t *testing.T) {
	p := newProject(t)
	p.init()
	for _, f := range []string{"config.encrypted.json", "config.unencrypted.json", "config.schema.json", ".gitignore", "jureuma.yaml", "AGENTS.md"} {
		if !p.exists(f) {
			t.Fatalf("init did not create %s", f)
		}
	}
	if n := len(p.keyFiles()); n != 1 {
		t.Fatalf("init generated %d keys, want 1", n)
	}
	if fi, err := os.Stat(p.keyFiles()[0]); err != nil || (fi.Mode().Perm()&0o077) != 0 {
		t.Fatalf("key file mode is too wide: %v", fi.Mode())
	}
	if fi, _ := os.Stat(p.path("config.unencrypted.json")); fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("unencrypted file mode is too wide: %v", fi.Mode())
	}
	meta := p.encMeta("config.encrypted.json")
	if meta["keyId"] == "" || !strings.HasPrefix(meta["publicKey"].(string), "jureuma-pk-1:") {
		t.Fatalf("bad $jureuma block: %v", meta)
	}

	projBefore := snapshot(t, p.dir)
	homeBefore := snapshot(t, p.home)
	r := p.init()
	if strings.Contains(r.stdout, "generated") {
		t.Fatalf("second init generated a key:\n%s", r)
	}
	if d := diffSnapshots(projBefore, snapshot(t, p.dir)); len(d) > 0 {
		t.Fatalf("second init changed project files: %v", d)
	}
	homeAfter := snapshot(t, p.home)
	var changed []string
	for _, f := range diffSnapshots(homeBefore, homeAfter) {
		// Only the audit log may grow; keys, configuration, state and skills stay.
		if !strings.HasSuffix(f, "audit.log") && !strings.HasSuffix(f, "audit.log (new)") {
			changed = append(changed, f)
		}
	}
	if len(changed) > 0 {
		t.Fatalf("second init changed home files: %v", changed)
	}
	if n := strings.Count(p.read(".gitignore"), "# >>> jureuma managed block >>>"); n != 1 {
		t.Fatalf(".gitignore has %d managed blocks", n)
	}

	// init on an existing encrypted file without its key never replaces the key.
	restore := p.hideKeys()
	before := p.read("config.encrypted.json")
	r = p.init()
	if !strings.Contains(r.out(), "private key not available") {
		t.Fatalf("init without the key should report it as informational:\n%s", r)
	}
	if p.read("config.encrypted.json") != before {
		t.Fatal("init modified $jureuma without the key")
	}
	if _, err := os.Stat(filepath.Join(p.jhome(), "keys")); err == nil {
		if files := p.keyFiles(); len(files) > 0 {
			t.Fatalf("init generated a key for an existing encrypted file: %v", files)
		}
		os.RemoveAll(filepath.Join(p.jhome(), "keys"))
	}
	restore()
}

func TestEncryptDecryptRoundTripKeepsOrderAndNumberText(t *testing.T) {
	needSh(t)
	p := newProject(t)
	const plain = `{"zeta":1,"alpha":{"b":1.0,"a":1e2,"c":-0.50},"num":100,"big":12345678901234567890.000,"arr":[3,"x",true,null,{}],"empty":[],"esc":"aé\"b","last":"Zz9"}`
	p.setup(plain)

	enc := p.read("config.encrypted.json")
	for _, v := range []string{"12345678901234567890", "Zz9"} {
		if strings.Contains(enc, v) {
			t.Fatalf("encrypted file contains plaintext %q", v)
		}
	}
	// $jureuma first, then keys in source order.
	order := []string{`"$jureuma"`, `"zeta"`, `"alpha"`, `"b"`, `"a"`, `"c"`, `"num"`, `"big"`, `"arr"`, `"empty"`, `"esc"`, `"last"`}
	last := -1
	body := enc
	for _, k := range order {
		i := strings.Index(body[last+1:], k)
		if i < 0 {
			t.Fatalf("encrypted file: key %s missing or out of order\n%s", k, enc)
		}
		last += 1 + i
	}
	if !strings.Contains(enc, `"empty": []`) || !strings.Contains(enc, "{}") {
		t.Fatalf("empty containers must stay as {} and []:\n%s", enc)
	}

	// encrypt again with no change: ciphertexts are reused.
	r := p.expect(0, "encrypt", "--keep-both")
	if p.read("config.encrypted.json") != enc {
		t.Fatalf("re-encrypting unchanged values changed the file:\n%s", r)
	}

	// The child sees the exact document text.
	if got := p.revealConfig(); got != `{"zeta":1,"alpha":{"b":1.0,"a":1e2,"c":-0.50},"num":100,"big":12345678901234567890.000,"arr":[3,"x",true,null,{}],"empty":[],"esc":"aé\"b","last":"Zz9"}` {
		t.Fatalf("JUREUMA_CONFIG = %s", got)
	}

	// decrypt recreates the plaintext with the same order and number text.
	p.remove("config.unencrypted.json")
	p.expect(0, "decrypt", "--keep-both", "--dangerously-bypass-protections")
	dec := p.read("config.unencrypted.json")
	want := `{"zeta":1,"alpha":{"b":1.0,"a":1e2,"c":-0.50},"num":100,"big":12345678901234567890.000,"arr":[3,"x",true,null,{}],"empty":[],"esc":"aé\"b","last":"Zz9"}`
	if stripWS(dec) != want && stripWS(dec) != stripWS(plain) {
		t.Fatalf("decrypted document differs:\n%s", dec)
	}
	if fi, _ := os.Stat(p.path("config.unencrypted.json")); fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("decrypted file mode is too wide: %v", fi.Mode())
	}
	if o, _ := p.statusJSON(); o != "in-sync" {
		t.Fatalf("status after decrypt: %s", o)
	}
}

func TestJSONCInput(t *testing.T) {
	needSh(t)
	p := newProject(t)
	p.init()
	p.remove("config.unencrypted.json")
	p.write("config.unencrypted.jsonc", `// leading comment
{
  /* block
     comment */
  "db": {
    "url": "jsonc-url-value", // trailing comment
    "pool": 5,
  },
  "tags": ["a", "b",],
}
`)
	p.expect(0, "encrypt", "--keep-both")
	enc := p.read("config.encrypted.json")
	if strings.Contains(enc, "comment") || strings.Contains(enc, "jsonc-url-value") {
		t.Fatalf("comments or values reached the encrypted file:\n%s", enc)
	}
	if got := p.revealConfig(); got != `{"db":{"url":"jsonc-url-value","pool":5},"tags":["a","b"]}` {
		t.Fatalf("JUREUMA_CONFIG = %s", got)
	}
	if o, _ := p.statusJSON(); o != "in-sync" {
		t.Fatalf("status: %s", o)
	}
	// jureuma never writes .jsonc: decrypt refuses, set leaves it alone.
	jsoncBefore := p.read("config.unencrypted.jsonc")
	if r := p.run("decrypt", "--keep-both", "--dangerously-bypass-protections"); r.code == 0 {
		t.Fatalf("decrypt wrote a .jsonc pair:\n%s", r)
	}
	p.expect(0, "set", "/db/url", "changed-by-set")
	if p.read("config.unencrypted.jsonc") != jsoncBefore {
		t.Fatal("set modified the .jsonc file")
	}
	if p.exists("config.unencrypted.json") {
		t.Fatal("set created a .json plaintext beside the .jsonc one")
	}
	_, states := p.statusJSON()
	if states["/db/url"] != "encrypted-newer" {
		t.Fatalf("after set on a .jsonc pair /db/url is %q, want encrypted-newer", states["/db/url"])
	}
	// Both .json and .jsonc present is a usage error for every command.
	p.write("config.unencrypted.json", `{}`)
	for _, args := range [][]string{{"status"}, {"encrypt", "--keep-both"}, {"list"}} {
		if r := p.run(args...); r.code != 2 {
			t.Fatalf("both plaintext variants present: want exit 2\n%s", r)
		}
	}
	// Strict .json input rejects comments, with line/column only.
	p.remove("config.unencrypted.jsonc")
	p.write("config.unencrypted.json", "{\n  \"a\": \"strict-secret-text\", // no\n}\n")
	r := p.run("encrypt", "--keep-both")
	if r.code == 0 || !strings.Contains(r.stderr, "line 2") {
		t.Fatalf("comment in .json must fail with a position:\n%s", r)
	}
	assertNo(t, "encrypt parse error", r.out(), "strict-secret-text", "no\n")
}

func TestGitignoreInvariant(t *testing.T) {
	p := newProject(t)
	p.setup(`{"a":"gitignore-value-1"}`)
	for _, f := range []string{"config.unencrypted.json", "x.unencrypted.jsonc", "deep/dir/y.unencrypted.json", "prod.unencrypted.json"} {
		if !p.gitOK("check-ignore", "-q", f) {
			t.Fatalf("%s is not ignored by git", f)
		}
	}

	// Without the block, the next write restores it.
	p.write(".gitignore", "node_modules/\n")
	p.remove("config.unencrypted.json")
	p.expect(0, "decrypt", "--keep-both", "--dangerously-bypass-protections")
	if !strings.Contains(p.read(".gitignore"), "*.unencrypted.json") || !strings.Contains(p.read(".gitignore"), "node_modules/") {
		t.Fatalf("block not restored (or user lines lost):\n%s", p.read(".gitignore"))
	}
	if !p.gitOK("check-ignore", "-q", "config.unencrypted.json") {
		t.Fatal("plaintext not ignored after restore")
	}

	// A negation rule after the block makes the file not ignorable: refuse to write.
	p.write(".gitignore", p.read(".gitignore")+"!config.unencrypted.json\n")
	plainBefore := p.read("config.unencrypted.json")
	r0 := p.expect(0, "set", "/b", "mirror-blocked-value")
	if p.read("config.unencrypted.json") != plainBefore || !strings.Contains(r0.stderr, "warning") {
		t.Fatalf("set mirrored into a plaintext file git does not ignore:\n%s", r0)
	}
	assertNo(t, "set warning", r0.out(), "mirror-blocked-value", "gitignore-value-1")
	p.remove("config.unencrypted.json")
	r := p.run("decrypt", "--keep-both", "--dangerously-bypass-protections")
	if r.code != 1 || p.exists("config.unencrypted.json") || !strings.Contains(r.stderr, "git does not ignore") {
		t.Fatalf("decrypt wrote a plaintext file git would not ignore:\n%s", r)
	}
	assertNo(t, "refusal", r.out(), "gitignore-value-1")
	p.write(".gitignore", strings.Replace(p.read(".gitignore"), "!config.unencrypted.json\n", "", 1))

	// A negation in a nested .gitignore is caught too.
	p.write("sub/.gitignore", "!*.unencrypted.json\n")
	p.write("jureuma.yaml", "pairs:\n  - name: config\n  - name: sub/app\n")
	r = p.run("init", "--agent-deny-rules", "no", "--agent-evolution", "always-ask")
	if r.code != 1 || !strings.Contains(r.stderr, "git does not ignore") {
		t.Fatalf("init must refuse a plaintext file git does not ignore:\n%s", r)
	}
	assertNo(t, "init refusal", r.out(), "gitignore-value-1")
	if p.exists("sub/app.unencrypted.json") {
		t.Fatalf("init wrote sub/app.unencrypted.json although git does not ignore it:\n%s", r)
	}
}

func TestNamedPairsAndFileFlags(t *testing.T) {
	needSh(t)
	p := newProject(t)
	p.write("jureuma.yaml", "pairs:\n  - name: config\n  - name: production\n")
	p.init()
	if !p.exists("production.encrypted.json") || !p.exists("production.schema.json") || !p.exists("config.encrypted.json") {
		t.Fatal("init did not create every configured pair")
	}
	if n := len(p.keyFiles()); n != 2 {
		t.Fatalf("want one key per new pair, have %d", n)
	}
	p.expect(0, "set", "--name", "production", "/mode", "prod-mode")
	p.expect(0, "set", "/mode", "dev-mode")
	if got := p.revealConfig("--name", "production"); got != `{"mode":"prod-mode"}` {
		t.Fatalf("production pair: %s", got)
	}
	// Explicit file paths must carry the state marker.
	for _, args := range [][]string{
		{"status", "--encrypted-file", "secrets.json"},
		{"status", "--unencrypted-file", "plain.json"},
	} {
		if r := p.run(args...); r.code != 2 {
			t.Fatalf("names without .encrypted./.unencrypted. must be refused with exit 2\n%s", r)
		}
	}
	p.expect(0, "status", "--encrypted-file", "production.encrypted.json")
}

func TestSchemaFileDisagreementOnMutatingCommand(t *testing.T) {
	p := newProject(t)
	p.init()
	p.write("jureuma.yaml", "pairs:\n  - name: config\n    schema: ./config.schema.json\n")
	p.write("loose.schema.json", `{"type":"object"}`)
	if r := p.run("set", "/a", "x", "--schema-file", "loose.schema.json"); r.code != 2 {
		t.Fatalf("--schema-file disagreeing with jureuma.yaml on set: want exit 2\n%s", r)
	}
	p.expect(0, "status", "--schema-file", "loose.schema.json")
}

func TestJSONOutputIsParseable(t *testing.T) {
	p := newProject(t)
	p.setup(`{"a":{"b":"json-output-value"},"n":3}`)
	r := p.expect(0, "list", "--output", "json")
	var l map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &l); err != nil {
		t.Fatalf("list --output json: %v\n%s", err, r)
	}
	assertNo(t, "list json", r.out(), "json-output-value")
	if !strings.Contains(r.stdout, `"A_B"`) || !strings.Contains(r.stdout, `"/n"`) {
		t.Fatalf("list json lacks paths or env names:\n%s", r)
	}
}
