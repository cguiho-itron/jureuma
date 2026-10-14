package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	sentinelA = "SENTINEL-cli-alpha-91"
	sentinelB = "SENTINEL-cli-bravo-17"
)

type harness struct {
	t     *testing.T
	home  string
	proj  string
	trans bytes.Buffer // every output that must stay free of sentinels
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, home: t.TempDir(), proj: t.TempDir()}
	t.Setenv("JUREUMA_USER_HOME", h.home)
	// HOME matches the override, so the bypass is not refused as relocated.
	t.Setenv("HOME", h.home)
	t.Setenv("USERPROFILE", h.home)
	t.Setenv("JUREUMA_NO_UPDATE_CHECK", "1")
	t.Setenv("JUREUMA_PRIVATE_KEY", "")
	if _, err := exec.LookPath("git"); err == nil {
		if out, err := exec.Command("git", "init", "-q", h.proj).CombinedOutput(); err != nil {
			t.Fatalf("git init: %v %s", err, out)
		}
	}
	t.Chdir(h.proj)
	return h
}

// run executes jureuma and records its output in the sentinel transcript.
func (h *harness) run(stdin string, args ...string) (int, string) {
	h.t.Helper()
	code, out := h.runRaw(stdin, args...)
	h.trans.WriteString(out)
	return code, out
}

func (h *harness) runRaw(stdin string, args ...string) (int, string) {
	var out bytes.Buffer
	code := ExecuteIO("1.2.3", args, strings.NewReader(stdin), &out, &out)
	return code, out.String()
}

func (h *harness) expect(code int, stdin string, args ...string) string {
	h.t.Helper()
	got, out := h.run(stdin, args...)
	if got != code {
		h.t.Fatalf("jureuma %s: exit %d, want %d\n%s", strings.Join(args, " "), got, code, out)
	}
	return out
}

func (h *harness) write(name, content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.proj, name), []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func TestEndToEndNoValueLeaks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	h := newHarness(t)
	h.expect(0, "", "init", "--agent-deny-rules", "yes")
	h.write("config.unencrypted.json", `{"db":{"url":"`+sentinelA+`","pool":5},"debug":false}`)
	h.expect(0, "", "schema", "infer")
	h.expect(0, "", "encrypt", "--keep-both")
	if out := h.expect(0, "", "list"); !strings.Contains(out, "DB_URL") || !strings.Contains(out, "number") {
		t.Fatalf("list output: %s", out)
	}
	h.expect(0, "", "status")
	h.expect(0, "", "check")
	h.expect(0, sentinelB+"\n", "set", "/token", "--allow-invalid", "--value-stdin")
	h.expect(4, "", "set", "/db/pool", "x")
	h.expect(0, "", "set", "/db/pool", "--json", "7")
	h.expect(0, "", "set", "/list", "--json", `["a","b","c"]`, "--allow-invalid")
	h.expect(0, "", "unset", "/list/0", "--allow-invalid")
	h.expect(1, "", "schema", "infer")
	h.expect(0, "", "schema", "infer", "--force")
	out := h.expect(0, "", "run", "--", "sh", "-c", `printf '%s\n' "$JUREUMA_CONFIG"`)
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("run output not redacted: %s", out)
	}
	out = h.expect(0, "", "run", "--format", "flatten", "--", "sh", "-c", `echo "$DB_URL $TOKEN $DB_POOL"`)
	if strings.TrimSpace(out) != "[REDACTED] [REDACTED] 7" {
		t.Fatalf("flatten output: %q", out)
	}
	if code, _ := h.run("", "run", "--", "sh", "-c", "exit 9"); code != 9 {
		t.Fatalf("child exit code not passed through: %d", code)
	}
	if code, out := h.run("", "run", "--format", "nope", "--", "true"); code != 125 || !strings.HasPrefix(out, "[JUREUMA:USAGE]") {
		t.Fatalf("run usage failure: %d %s", code, out)
	}
	// Human-only commands refuse without a terminal.
	for _, args := range [][]string{{"get", "/db/url"}, {"decrypt", "--keep-both"}, {"key", "show", "--private"}, {"key", "export"}} {
		code, out := h.run("", args...)
		if code != 3 || !strings.HasPrefix(out, "[PROTECTED] jureuma ") {
			t.Fatalf("%v: exit %d %s", args, code, out)
		}
	}
	h.expect(0, "", "key", "show")
	h.expect(0, "", "key", "rotate")
	h.expect(0, "", "status")

	// The transcript, the audit log and the committed files contain no value.
	audit, _ := os.ReadFile(filepath.Join(h.home, ".guiho", "jureuma", "audit.log"))
	enc, _ := os.ReadFile(filepath.Join(h.proj, "config.encrypted.json"))
	sch, _ := os.ReadFile(filepath.Join(h.proj, "config.schema.json"))
	for name, data := range map[string][]byte{"output": h.trans.Bytes(), "audit.log": audit, "encrypted": enc, "schema": sch} {
		for _, s := range []string{sentinelA, sentinelB} {
			if bytes.Contains(data, []byte(s)) {
				t.Fatalf("%s leaked a value:\n%s", name, data)
			}
		}
	}

	// With the bypass a human can read values (and the transcript check above is meaningful).
	code, out := h.runRaw("", "get", "/db/url", "--dangerously-bypass-protections")
	if code != 0 || !strings.Contains(out, sentinelA) {
		t.Fatalf("bypass get: %d %s", code, out)
	}
	code, _ = h.runRaw("", "decrypt", "--keep-both", "--dangerously-bypass-protections")
	if code != 0 {
		t.Fatal("bypass decrypt failed")
	}
	// The bypass is refused when disabled or when the protections block was edited by hand.
	global := filepath.Join(h.home, ".guiho", "jureuma", "jureuma.global.yaml")
	data, _ := os.ReadFile(global)
	edited := strings.Replace(string(data), "agentEnvMarkers: []", "agentEnvMarkers: [MY_AGENT]", 1)
	os.WriteFile(global, []byte(edited), 0o600)
	if code, _ := h.runRaw("", "get", "/db/url", "--dangerously-bypass-protections"); code != 3 {
		t.Fatalf("edited protections must refuse the bypass, got %d", code)
	}
	os.WriteFile(global, []byte(strings.Replace(string(data), "allowBypass: true", "allowBypass: false", 1)), 0o600)
	if code, _ := h.runRaw("", "get", "/db/url", "--dangerously-bypass-protections"); code != 3 {
		t.Fatalf("allowBypass false must refuse the bypass, got %d", code)
	}
}

func TestUsageAndHelp(t *testing.T) {
	h := newHarness(t)
	if out := h.expect(0, "", "--version"); out != "1.2.3\n" {
		t.Fatalf("--version printed %q", out)
	}
	if out := h.expect(0, "", "-v"); out != "1.2.3\n" {
		t.Fatalf("-v printed %q", out)
	}
	h.expect(2, "", "bogus")
	h.expect(2, "", "set")
	h.expect(2, "", "list", "--bogus")
	h.expect(2, "", "list", "--help-tree", "--help-tree-depth", "0")
	if out := h.expect(0, "", "set", "--help-docs"); !strings.HasPrefix(out, "# jureuma set\n") {
		t.Fatalf("help-docs: %s", out)
	}
	tree := h.expect(0, "", "--help-tree")
	for _, want := range []string{"init", "encrypt", "decrypt", "set", "unset", "get", "run", "list", "status", "check", "key", "rotate", "retire", "export", "schema", "infer", "juju-enable", "juju-disable", "agent", "skill", "instruction", "prompt", "upgrade", "uninstall", "--value-stdin", "--dangerously-bypass-protections"} {
		if !strings.Contains(tree, want) {
			t.Errorf("help tree lacks %s", want)
		}
	}
	if strings.Contains(tree, "__update-worker") {
		t.Error("hidden worker command shown")
	}
	shallow := h.expect(0, "", "agent", "--help-tree", "--help-tree-depth", "2")
	if strings.Contains(shallow, "install") {
		t.Error("depth 2 must not show grandchildren")
	}
	global := h.expect(0, "", "key", "--help-tree", "--help-tree-global-flags")
	if strings.Count(global, "--help-docs") < 5 {
		t.Error("global flags must repeat under every command")
	}
}

func TestAgentCommandsAndJuju(t *testing.T) {
	h := newHarness(t)
	out := h.expect(0, "", "agent", "prompt", "list")
	if !strings.Contains(out, "guiho-p-jureuma (default)") {
		t.Fatalf("prompt list: %s", out)
	}
	h.expect(0, "", "agent", "prompt", "show")
	h.expect(2, "", "agent", "prompt", "show", "nope")
	h.expect(0, "", "agent", "skill", "install")
	h.expect(0, "", "agent", "skill", "list")
	h.expect(0, "", "agent", "instruction", "apply")
	h.expect(0, "", "agent", "instruction", "upgrade")
	h.expect(0, "", "agent", "instruction", "remove")
	h.expect(1, "", "agent", "instruction", "upgrade")
	h.expect(0, "", "agent", "skill", "uninstall")

	bin := filepath.Join(h.home, ".guiho", "bin")
	os.MkdirAll(bin, 0o755)
	foreign := filepath.Join(bin, exeName("juju"))
	os.WriteFile(foreign, []byte("not ours"), 0o755)
	h.expect(1, "", "juju-enable")
	os.Remove(foreign)
	h.expect(0, "", "juju-enable")
	h.expect(0, "", "juju-enable")
	var st aliasState
	data, _ := os.ReadFile(filepath.Join(h.home, ".guiho", "jureuma", "state", aliasStateFile))
	if json.Unmarshal(data, &st) != nil || st.Path != foreign {
		t.Fatalf("alias state: %s", data)
	}
	h.expect(0, "", "juju-disable")
	if _, err := os.Stat(foreign); err == nil {
		t.Fatal("alias not removed")
	}
	h.expect(1, "", "juju-disable")
}

func TestUninstallPlan(t *testing.T) {
	h := newHarness(t)
	h.expect(0, "", "init")
	out := h.expect(0, "", "uninstall", "--dry-run")
	if !strings.Contains(out, "REMOVE") || !strings.Contains(out, "PRESERVE") || !strings.Contains(out, ".gitignore") {
		t.Fatalf("plan: %s", out)
	}
	h.expect(1, "", "uninstall")
	h.expect(0, "", "uninstall", "--yes", "--preserve-config")
	home := filepath.Join(h.home, ".guiho", "jureuma")
	if _, err := os.Stat(filepath.Join(home, "jureuma.global.yaml")); err != nil {
		t.Fatal("--preserve-config removed the global configuration")
	}
	if ents, _ := os.ReadDir(filepath.Join(home, "keys")); len(ents) == 0 {
		t.Fatal("keys must survive a non-interactive uninstall")
	}
	if _, err := os.Stat(filepath.Join(home, "state")); err == nil {
		t.Fatal("state should be removed without --preserve-data")
	}
	agents, _ := os.ReadFile(filepath.Join(h.proj, "AGENTS.md"))
	if strings.Contains(string(agents), "jureuma managed block") {
		t.Fatal("AGENTS.md block not removed")
	}
}
