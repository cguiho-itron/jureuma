package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Regression tests for the security, correctness and convention review.

func TestCommittedRunEnvNameCannotBeCodeLoading(t *testing.T) {
	needSh(t)
	p := newProject(t)
	p.setup(`{"a":"value-1"}`)
	marker := filepath.Join(p.home, "PWNED")
	// A committed run.envName that names a shell start-up variable is invalid.
	p.write("jureuma.yaml", "pairs:\n  - name: config\nrun:\n  format: file\n  envName: BASH_ENV\n")
	p.write("hello.sh", "#!/bin/bash\necho hello\n")
	os.Chmod(p.path("hello.sh"), 0o755)
	r := p.run("run", "--", "./hello.sh")
	if r.code == 0 {
		t.Fatalf("run with run.envName BASH_ENV must fail\n%s", r)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("code ran through BASH_ENV")
	}
	p.write("jureuma.yaml", "pairs:\n  - name: config\n")
	for _, name := range []string{"BASH_ENV", "PAGER", "GIT_SSH_COMMAND", "EDITOR"} {
		for _, format := range []string{"json", "file"} {
			if r := p.run("run", "--format", format, "--env-name", name, "--", "true"); r.code != 125 {
				t.Fatalf("--env-name %s --format %s: want 125\n%s", name, format, r)
			}
		}
	}
	// Keys that flatten to git configuration are refused.
	p.expectStdin(0, "1", "set", "/git_config_count", "--value-stdin")
	p.expectStdin(0, "core.fsmonitor", "set", "/git_config_key_0", "--value-stdin")
	if r := p.run("run", "--format", "flatten", "--", "true"); r.code != 125 || !strings.Contains(r.stderr, "denylisted") {
		t.Fatalf("flatten to GIT_CONFIG_*: want 125 denylisted\n%s", r)
	}
}

func TestArgumentsAreNeverEchoed(t *testing.T) {
	p := newProject(t)
	p.setup(`{"a":"value-1"}`)
	const secret = "SENTINELKEYMATERIAL7c1e"
	cases := [][]string{
		{"key", "export", "jureuma-sk-1:" + secret},
		{"key", "retire", "jureuma-sk-1:" + secret},
		{"set", "/token", "-S" + secret},
		{"set", "/token", "--" + secret},
		{"set", "/x", "--json=" + secret},
		{"run", "--" + secret},
		{"key", secret},
		{"help", secret},
		{secret},
	}
	for _, args := range cases {
		r := p.run(args...)
		if r.code == 0 && args[0] != "help" {
			t.Fatalf("want a failure\n%s", r)
		}
		if strings.Contains(r.out(), secret) {
			t.Fatalf("an argument was echoed\n%s", r)
		}
	}
	r := p.run("set", "/token", "-S"+secret)
	if !strings.Contains(r.stderr, "--value-stdin") {
		t.Fatalf("a dash value must point at -- or --value-stdin\n%s", r)
	}
}

func TestBypassRefusedWhenHomeIsRelocated(t *testing.T) {
	needSh(t)
	p := newProject(t)
	p.setup(`{"a":"relocated-value"}`)
	_, sk := p.privateKey()
	alt := t.TempDir()
	r := p.runEnv([]string{"JUREUMA_USER_HOME=" + alt, "JUREUMA_PRIVATE_KEY=" + sk}, "get", "/a", "--dangerously-bypass-protections")
	if r.code != 3 || strings.Contains(r.out(), "relocated-value") {
		t.Fatalf("bypass with a relocated home must be refused (exit 3)\n%s", r)
	}
}

func TestCommittedPathsStayInsideTheProject(t *testing.T) {
	p := newProject(t)
	outside := t.TempDir()
	p.write("jureuma.yaml", "pairs:\n  - name: config\n    schema: "+filepath.ToSlash(filepath.Join("..", filepath.Base(outside), "evil.schema.json"))+"\n")
	r := p.run("init", "--agent-deny-rules", "no", "--agent-evolution", "always-ask")
	if r.code == 0 {
		t.Fatalf("init with a schema outside the project must fail\n%s", r)
	}
	if _, err := os.Stat(filepath.Join(outside, "evil.schema.json")); err == nil {
		t.Fatal("init wrote outside the project")
	}

	q := newProject(t)
	q.setup(`{"a":"one1"}`)
	victim := filepath.Join(q.home, "victim.txt")
	q.writeAbs(victim, "precious")
	var m map[string]any
	if err := json.Unmarshal([]byte(q.read("config.encrypted.json")), &m); err != nil {
		t.Fatal(err)
	}
	rel, _ := filepath.Rel(q.dir, victim)
	m["$jureuma"].(map[string]any)["schema"] = filepath.ToSlash(rel)
	data, _ := json.MarshalIndent(m, "", "  ")
	q.write("config.encrypted.json", string(data))
	if r := q.run("schema", "infer", "--force"); r.code != 2 {
		t.Fatalf("schema infer through $jureuma.schema outside the project: want exit 2\n%s", r)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Fatal("schema infer overwrote a file outside the project")
	}
}

func TestSetNeverOverwritesUnsavedPlaintext(t *testing.T) {
	needSh(t)
	p := newProject(t)
	p.setup(`{"tags":["a1","b2"],"x":"one1"}`)
	p.write("config.unencrypted.json", `{"tags":["a1","b2","HUMAN_EDIT"],"x":"one1"}`)
	r := p.expect(0, "set", "/tags/-", "AGENT")
	if !strings.Contains(r.stderr, "not updated") {
		t.Fatalf("set must warn that the plaintext was left alone\n%s", r)
	}
	if !strings.Contains(p.read("config.unencrypted.json"), "HUMAN_EDIT") {
		t.Fatal("set overwrote the human's unsaved array element")
	}
	if o, _ := p.statusJSON(); o == "in-sync" {
		t.Fatal("status must not report in-sync after a skipped mirror")
	}
	// '-' only appends to an existing array.
	if r := p.run("set", "/newarr/-", "x"); r.code != 2 {
		t.Fatalf("set /newarr/- must be a usage error\n%s", r)
	}
	// A pointer deeper than the limit is refused before anything is written.
	if r := p.run("set", strings.Repeat("/a", 100), "v"); r.code != 2 {
		t.Fatalf("deep pointer: want exit 2\n%s", r)
	}
}

func TestSetTypeHintOnlyWithTypes(t *testing.T) {
	p := newProject(t)
	p.setup(`{"db":{"url":"u1"}}`)
	p.write("config.schema.json", `{"type":"object","additionalProperties":false,"properties":{"db":{"type":"object"},"a":false}}`)
	for _, ptr := range []string{"/extra", "/a"} {
		r := p.run("set", ptr, "v")
		if r.code != 4 || strings.Contains(r.stderr, "expects ,") || strings.Contains(r.stderr, "pass --json") {
			t.Fatalf("set %s: want a schema issue, not a type hint\n%s", ptr, r)
		}
	}
}

func TestSchemaFileCannotLoosenTheDefaultSchema(t *testing.T) {
	p := newProject(t)
	p.init()
	p.write("config.schema.json", `{"type":"object","properties":{"pool":{"type":"integer","maximum":10}}}`)
	p.write("config.unencrypted.json", `{"pool":5}`)
	p.expect(0, "encrypt", "--keep-both")
	p.write("loose.schema.json", `{}`)
	if r := p.run("set", "/pool", "--json", "99", "--schema-file", "loose.schema.json"); r.code != 2 {
		t.Fatalf("--schema-file disagreeing with config.schema.json: want exit 2\n%s", r)
	}
}

func TestDecryptKeepsEmptyContainerEdits(t *testing.T) {
	p := newProject(t)
	p.setup(`{"a":"one1"}`)
	p.write("config.unencrypted.json", `{"a":"one1","features":{},"hosts":[]}`)
	if r := p.run("decrypt", "--keep-both", "--dangerously-bypass-protections"); r.code == 0 {
		t.Fatalf("decrypt over new empty containers must refuse\n%s", r)
	}
	if !strings.Contains(p.read("config.unencrypted.json"), "features") {
		t.Fatal("decrypt dropped the structural edit")
	}
}

func TestUninstallKeepsForeignJuju(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX alias")
	}
	p := newProject(t)
	p.expect(0, "juju-enable")
	alias := filepath.Join(p.home, ".guiho", "bin", "juju")
	os.WriteFile(alias, []byte("#!/bin/sh\necho canonical juju\n"), 0o755)
	// A state file pointing elsewhere is never followed.
	outsideFile := filepath.Join(t.TempDir(), "precious")
	p.writeAbs(outsideFile, "keep")
	state := filepath.Join(p.jhome(), "state", "alias.json")
	data, _ := os.ReadFile(state)
	var st map[string]any
	json.Unmarshal(data, &st)
	st["path"] = outsideFile
	data, _ = json.Marshal(st)
	os.WriteFile(state, data, 0o600)

	r := p.expect(0, "uninstall", "--yes")
	if _, err := os.Stat(alias); err != nil {
		t.Fatalf("uninstall removed a juju jureuma does not own\n%s", r)
	}
	if _, err := os.Stat(outsideFile); err != nil {
		t.Fatalf("uninstall followed the path recorded in alias.json\n%s", r)
	}
}

func TestUpgradeForceDoesNotStopRunsWhenNothingIsInstalled(t *testing.T) {
	needSh(t)
	p := newProject(t)
	p.setup(`{"a":"one1"}`)
	cmd := exec.Command(binPath, "run", "--", "sh", "-c", "sleep 2; echo child-finished")
	cmd.Dir = p.dir
	cmd.Env = p.env
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	r := p.runEnv([]string{"JUREUMA_RELEASES_URL=http://127.0.0.1:1/none"}, "upgrade", "--force")
	if r.code == 0 {
		t.Fatalf("upgrade without a catalog must fail\n%s", r)
	}
	if err := cmd.Wait(); err != nil || !strings.Contains(out.String(), "child-finished") {
		t.Fatalf("a failed upgrade --force interrupted a run instance: %v %q", err, out.String())
	}
}

func TestSelfTestAndBareNotice(t *testing.T) {
	p := newProject(t)
	p.expect(0, "__self-test")
	cache := `{"latestVersion":"99.0.0","currentVersion":"` + testVersion + `","newVersionAvailable":true,"lastCheck":"` + time.Now().UTC().Format(time.RFC3339) + `","upgradeCommand":"jureuma upgrade"}`
	p.writeAbs(filepath.Join(p.jhome(), "cache.json"), cache)
	env := []string{"JUREUMA_NO_UPDATE_CHECK="}
	if r := p.runEnv(env, "--help-tree-depth", "3"); strings.Contains(r.stderr, "New version available") {
		t.Fatalf("a root invocation with flags must not print the notice\n%s", r)
	}
	if r := p.runEnv(env); !strings.Contains(r.stderr, "New version available") {
		t.Fatalf("the bare invocation must print the notice\n%s", r)
	}
}

func TestCheckReportsStaleTempFiles(t *testing.T) {
	p := newProject(t)
	p.setup(`{"a":"one1"}`)
	p.write(".config.tmp-123456.unencrypted.json", `{"a":"one1"}`)
	if out := p.git("check-ignore", ".config.tmp-123456.unencrypted.json"); !strings.Contains(out, "tmp-123456") {
		t.Fatalf("a crash-left temp file is not git-ignored: %q", out)
	}
	r := p.run("check")
	if !strings.Contains(r.stdout+r.stderr, ".config.tmp-123456.unencrypted.json") {
		t.Fatalf("check must report the stale temp file\n%s", r)
	}
}
