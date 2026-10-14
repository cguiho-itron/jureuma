package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSchemaInferThenValidation(t *testing.T) {
	p := newProject(t)
	const v1, v2 = "schema-value-original", "schema-value-bad"
	p.setup(`{"server":{"port":8080,"host":"` + v1 + `"},"tags":["a","b"],"mixed":[1,"x"],"empty":[],"on":true}`)
	r := p.expect(0, "schema", "infer")
	assertNo(t, "schema infer output", r.out(), v1)

	var sch map[string]any
	raw := p.read("config.schema.json")
	if err := json.Unmarshal([]byte(raw), &sch); err != nil {
		t.Fatalf("inferred schema is not JSON: %v", err)
	}
	assertNo(t, "inferred schema", raw, v1, "8080")
	if sch["additionalProperties"] != false || sch["type"] != "object" {
		t.Fatalf("root schema: %v", sch)
	}
	props := sch["properties"].(map[string]any)
	server := props["server"].(map[string]any)
	if server["properties"].(map[string]any)["port"].(map[string]any)["type"] == nil {
		t.Fatalf("port type not inferred: %s", raw)
	}
	if _, ok := props["mixed"].(map[string]any)["prefixItems"]; !ok {
		t.Fatalf("mixed arrays must become prefixItems: %s", raw)
	}
	if _, ok := props["tags"].(map[string]any)["items"]; !ok {
		t.Fatalf("homogeneous arrays must become items: %s", raw)
	}
	// An existing (non-starter) schema is not overwritten without --force.
	if r := p.run("schema", "infer"); r.code == 0 {
		t.Fatalf("schema infer overwrote a schema without --force\n%s", r)
	}
	if p.read("config.schema.json") != raw {
		t.Fatal("refused schema infer changed the schema")
	}
	// check no longer warns about the starter schema.
	if r := p.expect(0, "check"); strings.Contains(r.stdout, "starter") {
		t.Fatalf("check still reports the starter schema\n%s", r)
	}

	// A plaintext edit that breaks the schema: encrypt exits 4 naming only the path.
	enc := p.read("config.encrypted.json")
	p.write("config.unencrypted.json", `{"server":{"port":"`+v2+`","host":"`+v1+`"},"tags":["a","b"],"mixed":[1,"x"],"empty":[],"on":true}`)
	r = p.run("encrypt", "--keep-both")
	if r.code != 4 || !strings.Contains(r.out(), "/server/port") {
		t.Fatalf("schema violation: want exit 4 naming /server/port\n%s", r)
	}
	assertNo(t, "validation failure", r.out(), v1, v2)
	if p.read("config.encrypted.json") != enc {
		t.Fatal("failed encrypt wrote the encrypted file")
	}
	// set validates provisionally.
	r = p.run("set", "/server/port", "--json", `"`+v2+`"`)
	if r.code != 4 {
		t.Fatalf("set of a string into a number: want exit 4\n%s", r)
	}
	assertNo(t, "set validation failure", r.out(), v2)
	r = p.run("set", "/server/nope", v2)
	if r.code != 4 {
		t.Fatalf("set of an unknown property: want exit 4\n%s", r)
	}
	assertNo(t, "set validation failure", r.out(), v2)
	if p.read("config.encrypted.json") != enc {
		t.Fatal("failed set wrote the encrypted file")
	}

	// A .schema.jsonc file with comments is supported, refinements apply.
	p.write("config.unencrypted.json", `{"server":{"port":8080,"host":"`+v1+`"},"tags":["a","b"],"mixed":[1,"x"],"empty":[],"on":true}`)
	os.Remove(p.path("config.schema.json"))
	p.write("config.schema.jsonc", `{
  // refined by an agent
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "server": {"type": "object", "properties": {"port": {"type": "integer", "maximum": 100,},},},
  },
}`)
	r = p.run("encrypt", "--keep-both")
	if r.code != 4 || !strings.Contains(r.out(), "maximum") {
		t.Fatalf("jsonc schema maximum: want exit 4\n%s", r)
	}
	assertNo(t, "maximum failure", r.out(), "8080", v1)
	// Unknown keywords and unsupported formats are errors.
	os.Remove(p.path("config.schema.jsonc"))
	p.write("config.schema.json", `{"type":"object","propertys":{}}`)
	if r := p.run("check"); r.code != 4 {
		t.Fatalf("unknown keyword: want exit 4\n%s", r)
	}
	p.write("config.schema.json", `{"type":"object","properties":{"server":{"format":"emial"}}}`)
	if r := p.run("check"); r.code != 4 {
		t.Fatalf("unknown format: want exit 4\n%s", r)
	}
	p.write("config.schema.json", `{"type":"object","x-note":"annotations are fine"}`)
	p.expect(0, "check")
}

func TestSchemaInferFromEncryptedOnly(t *testing.T) {
	p := newProject(t)
	p.setup(`{"a":{"b":"enc-only-value"},"n":[1,2]}`)
	p.remove("config.unencrypted.json")
	r := p.expect(0, "schema", "infer")
	raw := p.read("config.schema.json")
	assertNo(t, "schema", raw+r.out(), "enc-only-value")
	if !strings.Contains(raw, `"a"`) || !strings.Contains(raw, `"b"`) {
		t.Fatalf("structure not inferred from the encrypted file: %s", raw)
	}
}

func TestVersionIsRaw(t *testing.T) {
	p := newProject(t)
	for _, args := range [][]string{{"--version"}, {"-v"}} {
		r := p.expect(0, args...)
		if r.stdout != testVersion+"\n" || r.stderr != "" {
			t.Fatalf("%v printed %q / %q", args, r.stdout, r.stderr)
		}
	}
}

func TestHelpTreeOnSubcommand(t *testing.T) {
	p := newProject(t)
	r := p.expect(0, "key", "--help-tree")
	for _, want := range []string{"show", "export", "rotate", "retire", "--private", "--dangerously-bypass-protections"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("key --help-tree lacks %s:\n%s", want, r.stdout)
		}
	}
	for _, not := range []string{"── encrypt", "── juju-enable", "── uninstall", "── infer", "── init"} {
		if strings.Contains(r.stdout, not) {
			t.Fatalf("key --help-tree shows %s outside the subtree:\n%s", not, r.stdout)
		}
	}
	r = p.expect(0, "agent", "skill", "--help-tree")
	if !strings.Contains(r.stdout, "── install") || strings.Contains(r.stdout, "── instruction") {
		t.Fatalf("agent skill --help-tree:\n%s", r.stdout)
	}
	r = p.expect(0, "run", "--help-tree")
	for _, want := range []string{"--format", "--env-name", "--env", "--prefix", "--override"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("run --help-tree lacks %s:\n%s", want, r.stdout)
		}
	}
	shallow := p.expect(0, "agent", "--help-tree", "--help-tree-depth", "2")
	if strings.Contains(shallow.stdout, "── uninstall") || !strings.Contains(shallow.stdout, "── skill") {
		t.Fatalf("depth 1 shows grandchildren:\n%s", shallow.stdout)
	}
	// The convention allows max or an integer greater than 1.
	for _, d := range []string{"0", "1", "x"} {
		if r := p.run("key", "--help-tree", "--help-tree-depth", d); r.code != 2 {
			t.Fatalf("depth %s: want exit 2\n%s", d, r)
		}
	}
	// Help flags work even when required arguments are missing.
	r = p.expect(0, "set", "--help-docs")
	if !strings.HasPrefix(r.stdout, "# jureuma set") {
		t.Fatalf("set --help-docs:\n%s", r.stdout)
	}
	p.expect(0, "unset", "--help")
	if r := p.run("nope-command"); r.code != 2 {
		t.Fatalf("unknown command: want exit 2\n%s", r)
	}
	if r := p.run("list", "--nope"); r.code != 2 {
		t.Fatalf("unknown flag: want exit 2\n%s", r)
	}
}

func TestEnableDisableJuju(t *testing.T) {
	p := newProject(t)
	p.setup(`{"a":"juju-value"}`)
	binDir := filepath.Join(p.home, ".guiho", "bin")
	alias := filepath.Join(binDir, "juju")
	if runtime.GOOS == "windows" {
		alias += ".exe"
	}
	// A juju that jureuma does not own is never overwritten.
	p.writeAbs(alias, "#!/bin/sh\necho foreign\n")
	os.Chmod(alias, 0o755)
	if r := p.run("juju-enable"); r.code == 0 {
		t.Fatalf("juju-enable overwrote a foreign juju\n%s", r)
	}
	if data, _ := os.ReadFile(alias); !strings.Contains(string(data), "foreign") {
		t.Fatal("foreign juju was modified")
	}
	if r := p.run("juju-disable"); r.code == 0 {
		t.Fatalf("juju-disable removed a juju it does not own\n%s", r)
	}
	if _, err := os.Stat(alias); err != nil {
		t.Fatal("foreign juju was removed")
	}
	os.Remove(alias)

	p.expect(0, "juju-enable")
	p.expect(0, "juju-enable") // idempotent
	if _, err := os.Stat(filepath.Join(p.jhome(), "state", "alias.json")); err != nil {
		t.Fatalf("alias not recorded in state/alias.json: %v", err)
	}
	// juju behaves exactly like jureuma.
	cmd := exec.Command(alias, "--version")
	cmd.Dir = p.dir
	cmd.Env = p.env
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != testVersion+"\n" {
		t.Fatalf("juju --version: %v %q", err, out)
	}
	cmd = exec.Command(alias, "status", "--output", "json")
	cmd.Dir = p.dir
	cmd.Env = p.env
	out, err = cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), `"overall": "in-sync"`) {
		t.Fatalf("juju status: %v %s", err, out)
	}
	cmd = exec.Command(alias, "get", "/a")
	cmd.Dir = p.dir
	cmd.Env = p.env
	out, _ = cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 3 || strings.Contains(string(out), "juju-value") {
		t.Fatalf("juju get must be gated like jureuma get: %d %s", cmd.ProcessState.ExitCode(), out)
	}

	p.expect(0, "juju-disable")
	if _, err := os.Stat(alias); err == nil {
		t.Fatal("juju-disable left the alias")
	}
	if r := p.run("juju-disable"); r.code == 0 {
		t.Fatalf("juju-disable without an alias must fail\n%s", r)
	}
	// A changed alias is not removed without --force.
	p.expect(0, "juju-enable")
	os.WriteFile(alias, []byte("#!/bin/sh\necho changed\n"), 0o755)
	if r := p.run("juju-disable"); r.code == 0 {
		t.Fatalf("juju-disable removed a changed alias without --force\n%s", r)
	}
	p.expect(0, "juju-disable", "--force")
	if _, err := os.Stat(alias); err == nil {
		t.Fatal("juju-disable --force left the alias")
	}
}

func TestKeyRotateAndRetire(t *testing.T) {
	needSh(t)
	p := newProject(t)
	p.setup(`{"a":"rotate-value","n":[1,2]}`)
	oldID, oldSK := p.privateKey()
	r := p.expect(0, "key", "rotate")
	assertNo(t, "rotate output", r.out(), "rotate-value", oldSK)
	newID := p.encMeta("config.encrypted.json")["keyId"].(string)
	if newID == oldID {
		t.Fatal("rotate kept the key ID")
	}
	if !strings.Contains(r.stdout, "JUREUMA_PRIVATE_KEY_"+strings.ToUpper(newID)) {
		t.Fatalf("rotate must print the new CI variable name\n%s", r)
	}
	if strings.Contains(p.read("config.encrypted.json"), oldID) {
		t.Fatal("ciphertexts under the old key remain after rotate")
	}
	if _, err := os.Stat(filepath.Join(p.jhome(), "keys", "retired", oldID+".json")); err != nil {
		t.Fatalf("old key not retired: %v", err)
	}
	if got := p.revealConfig(); got != `{"a":"rotate-value","n":[1,2]}` {
		t.Fatalf("after rotate: %s", got)
	}
	if o, _ := p.statusJSON(); o != "in-sync" {
		t.Fatalf("status after rotate: %s", o)
	}
	p.expect(0, "key", "retire", oldID)
	if _, err := os.Stat(filepath.Join(p.jhome(), "keys", "retired", oldID+".json")); err == nil {
		t.Fatal("retire left the key")
	}
	if r := p.run("key", "retire", newID); r.code == 0 {
		t.Fatalf("retiring the active key must fail\n%s", r)
	}
}
