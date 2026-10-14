package e2e

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The sentinel values are unique strings planted in the configuration. No
// command run without --dangerously-bypass-protections may display them, in
// any encoding, on stdout or stderr, nor write them to the audit log or to a
// committed file.
const (
	sentinelA = "SENTINEL-e2e-7f3a9c41d2"
	sentinelB = "SENTINEL-e2e-b8e06215aa"
	sentinelC = "SENTINEL-e2e-c19d44e0f7"
)

func sentinelForms() []string {
	var out []string
	for _, s := range []string{sentinelA, sentinelB, sentinelC} {
		out = append(out, s, base64.StdEncoding.EncodeToString([]byte(s)), base64.RawURLEncoding.EncodeToString([]byte(s)))
	}
	// A distinctive fragment catches truncated or partially quoted echoes.
	out = append(out, "7f3a9c41d2", "b8e06215aa", "c19d44e0f7")
	return out
}

func TestSentinelNeverDisplayed(t *testing.T) {
	needSh(t)
	p := newProject(t)
	p.expect(0, "init", "--agent-deny-rules", "yes", "--agent-evolution", "always-ask")
	p.write("config.unencrypted.json", `{"db":{"url":"`+sentinelA+`","pool":5},"flags":["`+sentinelA+`"],"debug":false}`)
	p.expect(0, "schema", "infer")
	p.expect(0, "encrypt", "--keep-both")
	keyID, sk := p.privateKey()

	type step struct {
		stdin string
		env   []string
		args  []string
	}
	agent := []string{"CLAUDECODE=1"}
	steps := []step{
		{args: []string{"status"}},
		{args: []string{"status", "--output", "json"}},
		{args: []string{"list"}},
		{args: []string{"list", "--output", "json"}},
		{args: []string{"check"}},
		{args: []string{"key", "show"}},
		{args: []string{"encrypt", "--keep-both"}},
		// set never echoes, and failing sets never echo either.
		{stdin: sentinelB + "\n", args: []string{"set", "/token", "--value-stdin", "--allow-invalid"}},
		{stdin: sentinelB + "\n", args: []string{"set", "/db/pool", "--value-stdin"}},                                        // string for a number: exit 4
		{args: []string{"set", "/db/pool", "--json", `"` + sentinelC + `"`}},                                                 // wrong type: exit 4
		{args: []string{"set", "/db/pool", "--json", sentinelC}},                                                             // invalid JSON
		{args: []string{"set", "/db/pool", "--json", `{"x":"` + sentinelC + `" oops}`}},                                      // invalid JSON
		{args: []string{"set", "/unknown", sentinelC}},                                                                       // additionalProperties
		{args: []string{"set", "/db/url/below", sentinelC}},                                                                  // through a leaf
		{args: []string{"set", "/db/url", sentinelC, "--value-stdin"}, stdin: sentinelC},                                     // two sources
		{args: []string{"set", sentinelC, "x"}},                                                                              // pointer is not a value, but must not matter
		{args: []string{"unset", "/db/url"}},                                                                                 // required
		{args: []string{"get", "/db/url"}},                                                                                   // refused
		{env: agent, args: []string{"get", "/db/url"}},                                                                       // refused
		{args: []string{"get", "/flags"}},                                                                                    // refused
		{args: []string{"decrypt", "--keep-both"}},                                                                           // refused
		{args: []string{"key", "export"}},                                                                                    // refused
		{args: []string{"key", "export", keyID}},                                                                             // refused
		{args: []string{"key", "show", "--private"}},                                                                         // refused
		{args: []string{"run", "--", "sh", "-c", `printf '%s\n' "$JUREUMA_CONFIG"; printf '%s' "$JUREUMA_CONFIG" | base64`}}, // redacted
		{args: []string{"run", "--format", "flatten", "--", "sh", "-c", `echo "$DB_URL $FLAGS_0 $TOKEN" >&2`}},
		{args: []string{"run", "--format", "file", "--", "sh", "-c", `cat "$JUREUMA_CONFIG"`}},
		{args: []string{"run", "--env", "U=/db/url", "--", "sh", "-c", `printf '%s' "$U"; printf '%s' "$U" | od -c | head -1 >/dev/null`}},
		{args: []string{"run", "--env", "U=" + sentinelC, "--", "true"}}, // bad pointer in --env
		{args: []string{"status"}},
		{args: []string{"check"}},
		{args: []string{"schema", "infer", "--force"}},
		{args: []string{"encrypt", "--keep-both"}},
		{args: []string{"key", "rotate"}},
		{args: []string{"status"}},
		{args: []string{"run", "--", "env"}},
		{args: []string{"--help-tree"}},
		{args: []string{"uninstall", "--dry-run"}},
	}
	for _, s := range steps {
		r := p.execIn(p.dir, s.env, s.stdin, s.args...)
		for _, f := range sentinelForms() {
			if strings.Contains(r.out(), f) {
				t.Fatalf("output displays a sentinel value (%q)\n%s", f, r)
			}
		}
	}

	// Validation and parse failures that involve the plaintext file.
	p.expect(0, "decrypt", "--keep-both", "--dangerously-bypass-protections")
	bad := []string{
		`{"db":{"url":"` + sentinelA + `","pool":"` + sentinelC + `"},"flags":["x"],"debug":false,"token":"t"}`, // schema type
		`{"db":{"url":"` + sentinelA + `","pool":5},"flags":["x"],"debug":false,"token":"t","extra":"` + sentinelC + `"}`,
		`{"db":{"url":"` + sentinelA + `" ` + sentinelC + `}}`, // syntax error right at a value
		`{"db":{"url":"` + sentinelC + "\x00" + `"}}`,
		`{"a":"` + sentinelC + `","a":"` + sentinelC + `"}`, // duplicate key
	}
	for _, doc := range bad {
		p.write("config.unencrypted.json", doc)
		for _, args := range [][]string{{"encrypt", "--keep-both"}, {"status"}, {"check"}, {"schema", "infer", "--force"}} {
			r := p.run(args...)
			for _, f := range sentinelForms() {
				if strings.Contains(r.out(), f) {
					t.Fatalf("output displays a sentinel value (%q)\n%s", f, r)
				}
			}
		}
	}
	// A schema that rejects the decrypted document: run and check fail without values.
	p.write("config.schema.json", `{"type":"object","properties":{"db":{"type":"object","properties":{"url":{"type":"string","maxLength":3,"pattern":"^x$","enum":["a"],"format":"email"}}}}}`)
	for _, args := range [][]string{{"run", "--", "true"}, {"check"}, {"set", "/db/url", sentinelC}} {
		r := p.run(args...)
		if r.code == 0 {
			t.Fatalf("expected a validation failure\n%s", r)
		}
		for _, f := range sentinelForms() {
			if strings.Contains(r.out(), f) {
				t.Fatalf("output displays a sentinel value (%q)\n%s", f, r)
			}
		}
	}

	// Files that are committed or logged never hold a value either.
	files := map[string]string{
		"audit.log":             p.auditLog(),
		"config.encrypted.json": p.read("config.encrypted.json"),
		"config.schema.json":    p.read("config.schema.json"),
		"jureuma.yaml":          p.read("jureuma.yaml"),
		".gitignore":            p.read(".gitignore"),
		"AGENTS.md":             p.read("AGENTS.md"),
	}
	if data, err := os.ReadFile(filepath.Join(p.dir, ".claude", "settings.json")); err == nil {
		files[".claude/settings.json"] = string(data)
	}
	for name, data := range files {
		for _, f := range append(sentinelForms(), sk, strings.TrimPrefix(sk, "jureuma-sk-1:")) {
			if strings.Contains(data, f) {
				t.Fatalf("%s contains a value or key material (%q)", name, f)
			}
		}
	}
	// The whole transcript (every non-bypass command above) never shows key material.
	tr := p.trans.String()
	for _, f := range []string{sk, strings.TrimPrefix(sk, "jureuma-sk-1:")} {
		if strings.Contains(tr, f) {
			t.Fatal("transcript contains private key material")
		}
	}

	// Control: the bypass does reveal the sentinel, so the checks above are meaningful.
	p.write("config.schema.json", `{"type":"object"}`)
	r := p.expect(0, "get", "/db/url", "--dangerously-bypass-protections")
	if !strings.Contains(r.stdout, sentinelA) {
		t.Fatalf("control: bypass get did not print the sentinel\n%s", r)
	}
}
