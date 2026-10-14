package e2e

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const protectedPrefix = "[PROTECTED] jureuma "

func TestHumanOnlyCommandsRefuseWithoutTerminal(t *testing.T) {
	p := newProject(t)
	const secret = "human-only-secret-value"
	p.setup(`{"db":{"password":"` + secret + `"}}`)
	keyID, sk := p.privateKey()
	commands := [][]string{
		{"get", "/db/password"},
		{"decrypt", "--keep-both"},
		{"key", "export"},
		{"key", "export", keyID},
		{"key", "show", "--private"},
	}
	envs := [][]string{
		nil,
		{"CLAUDECODE=1"},
		{"JUREUMA_AGENT=1"},
		{"CODEX_SANDBOX=seatbelt"},
	}
	plainBefore := p.read("config.unencrypted.json")
	p.remove("config.unencrypted.json")
	for _, env := range envs {
		for _, args := range commands {
			r := p.runEnv(env, args...)
			if r.code != 3 || !strings.HasPrefix(r.stderr, protectedPrefix) || !strings.Contains(r.stderr, "is human-only. A human must run it in an interactive terminal.") {
				t.Fatalf("env %v: want exit 3 [PROTECTED]\n%s", env, r)
			}
			if strings.Contains(r.out(), "dangerously") {
				t.Fatalf("refusal hints at the bypass flag\n%s", r)
			}
			assertNo(t, "refusal", r.out(), secret, sk, strings.TrimPrefix(sk, "jureuma-sk-1:"))
		}
	}
	if p.exists("config.unencrypted.json") {
		t.Fatal("refused decrypt wrote the plaintext file")
	}
	p.write("config.unencrypted.json", plainBefore)
	// key show without --private is not protected and never prints the key.
	r := p.expect(0, "key", "show")
	if !strings.Contains(r.stdout, keyID) || !strings.Contains(r.stdout, "jureuma-pk-1:") {
		t.Fatalf("key show:\n%s", r)
	}
	assertNo(t, "key show", r.out(), sk, strings.TrimPrefix(sk, "jureuma-sk-1:"))

	// Refusals are audited, without values.
	events := p.auditEvents()
	refused := 0
	for _, ev := range events {
		if ev["outcome"] == "refused" {
			refused++
		}
	}
	if refused < len(commands)*len(envs) {
		t.Fatalf("want every refusal audited, have %d refused events", refused)
	}
	assertNo(t, "audit.log", p.auditLog(), secret, sk)
}

// TestAgentMarkerRefusesUnderTerminal runs get inside a pseudo-terminal (via
// script(1)) so only the agent-marker check can refuse it.
func TestAgentMarkerRefusesUnderTerminal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses util-linux script(1)")
	}
	scriptBin, err := exec.LookPath("script")
	if err != nil {
		t.Skip("script(1) not installed")
	}
	p := newProject(t)
	p.setup(`{"k":"pty-secret-value"}`)
	cmdline := binPath + " get /k"
	runPTY := func(env []string) (string, int) {
		cmd := exec.Command(scriptBin, "-qec", cmdline, "/dev/null")
		cmd.Dir = p.dir
		cmd.Env = mergeEnv(p.env, env)
		cmd.Stdin = strings.NewReader("")
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("script: %v", err)
		}
		return string(out), code
	}
	// Sanity: with a terminal and no marker the gate asks for the word.
	out, code := runPTY(nil)
	if !strings.Contains(out, "type \"") {
		t.Skipf("script(1) did not provide a terminal (exit %d): %s", code, out)
	}
	if code != 3 || strings.Contains(out, "pty-secret-value") {
		t.Fatalf("unanswered confirmation must refuse with exit 3 (exit %d):\n%s", code, out)
	}
	for _, marker := range []string{"CLAUDECODE=1", "GEMINI_CLI=1"} {
		out, code := runPTY([]string{marker})
		if code != 3 || !strings.Contains(out, protectedPrefix) || strings.Contains(out, "type \"") {
			t.Fatalf("%s under a terminal: want exit 3 without a prompt (exit %d):\n%s", marker, code, out)
		}
		if strings.Contains(out, "pty-secret-value") {
			t.Fatal("value leaked")
		}
	}
}

// TestHumanConfirmationUnderTerminal types the confirmation word shown in a
// pseudo-terminal: the human path of get and decrypt works without the bypass.
func TestHumanConfirmationUnderTerminal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses util-linux script(1)")
	}
	scriptBin, err := exec.LookPath("script")
	if err != nil {
		t.Skip("script(1) not installed")
	}
	p := newProject(t)
	p.setup(`{"k":"human-typed-value"}`)
	wordRe := regexp.MustCompile(`type "([^"]+)" to ([^:]+):`)
	confirm := func(answer func(word string) string, args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(scriptBin, "-qec", binPath+" "+strings.Join(args, " "), "/dev/null")
		cmd.Dir = p.dir
		cmd.Env = p.env
		stdin, _ := cmd.StdinPipe()
		var mu sync.Mutex
		var buf bytes.Buffer
		cmd.Stdout = writerFunc(func(b []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return buf.Write(b) })
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			m := wordRe.FindStringSubmatch(buf.String())
			mu.Unlock()
			if m != nil {
				io.WriteString(stdin, answer(m[1])+"\n")
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		err := cmd.Wait()
		stdin.Close()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		mu.Lock()
		defer mu.Unlock()
		return buf.String(), code
	}
	out, code := confirm(func(w string) string { return w }, "get", "/k")
	if !strings.Contains(out, "type \"") {
		t.Skipf("script(1) did not provide a terminal (exit %d): %s", code, out)
	}
	if code != 0 || !strings.Contains(out, "human-typed-value") || !strings.Contains(out, "reveal 1 value") {
		t.Fatalf("typed confirmation: exit %d\n%s", code, out)
	}
	// A plain "y" is not enough.
	out, code = confirm(func(string) string { return "y" }, "get", "/k")
	if code != 3 || strings.Contains(out, "human-typed-value") {
		t.Fatalf("answering y must refuse: exit %d\n%s", code, out)
	}
	p.remove("config.unencrypted.json")
	_, code = confirm(func(w string) string { return w }, "decrypt", "--keep-both")
	if code != 0 || !strings.Contains(p.read("config.unencrypted.json"), "human-typed-value") {
		t.Fatalf("typed confirmation for decrypt: exit %d", code)
	}
	outcomes := map[string]int{}
	for _, ev := range p.auditEvents() {
		outcomes[ev["outcome"].(string)]++
	}
	if outcomes["allowed"] != 2 || outcomes["refused"] != 1 {
		t.Fatalf("audit outcomes: %v", outcomes)
	}
	assertNo(t, "audit.log", p.auditLog(), "human-typed-value")
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

func TestBypassFlag(t *testing.T) {
	p := newProject(t)
	const secret = "bypass-secret-value"
	p.setup(`{"db":{"password":"` + secret + `"},"n":42}`)
	_, sk := p.privateKey()

	r := p.expectEnv(0, []string{"CLAUDECODE=1"}, "get", "/db/password", "--dangerously-bypass-protections")
	if r.stdout != secret+"\n" {
		t.Fatalf("get with bypass printed %q", r.stdout)
	}
	if !strings.Contains(r.stderr, "warning") {
		t.Fatalf("bypass must warn on stderr\n%s", r)
	}
	r = p.expect(0, "get", "/n", "--dangerously-bypass-protections")
	if strings.TrimSpace(r.stdout) != "42" {
		t.Fatalf("get /n printed %q", r.stdout)
	}
	r = p.expect(0, "key", "export", "--dangerously-bypass-protections")
	if strings.TrimSpace(r.stdout) != sk {
		t.Fatalf("key export printed something else\n%s", r)
	}
	p.remove("config.unencrypted.json")
	p.expect(0, "decrypt", "--keep-both", "--dangerously-bypass-protections")
	if !strings.Contains(p.read("config.unencrypted.json"), secret) {
		t.Fatal("decrypt did not write the value")
	}

	events := p.auditEvents()
	bypassed := 0
	var sawMarker bool
	for _, ev := range events {
		if ev["outcome"] == "bypassed" && ev["bypass"] == true {
			bypassed++
			if ms, _ := ev["markers"].([]any); len(ms) > 0 && ms[0] == "CLAUDECODE" {
				sawMarker = true
			}
		}
		if ev["command"] == nil || ev["time"] == nil {
			t.Fatalf("audit event lacks command/time: %v", ev)
		}
	}
	if bypassed != 4 || !sawMarker {
		t.Fatalf("want 4 bypassed events with the caller's markers, got %d (marker %v)\n%s", bypassed, sawMarker, p.auditLog())
	}
	assertNo(t, "audit.log", p.auditLog(), secret, sk, strings.TrimPrefix(sk, "jureuma-sk-1:"), "42}")
	if fi, err := os.Stat(filepath.Join(p.jhome(), "audit.log")); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("audit.log mode: %v %v", fi, err)
	}
	// Only protected operations (and run) accept the flag.
	for _, args := range [][]string{{"set", "/x", "y", "--dangerously-bypass-protections"}, {"list", "--dangerously-bypass-protections"}} {
		if r := p.run(args...); r.code != 2 {
			t.Fatalf("non-protected command accepted the bypass flag\n%s", r)
		}
	}
}

func TestAllowBypassFalseAndTamperedProtections(t *testing.T) {
	p := newProject(t)
	p.setup(`{"k":"protections-secret"}`)
	global := filepath.Join(p.jhome(), "jureuma.global.yaml")
	orig, err := os.ReadFile(global)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(orig), "allowBypass: true") {
		t.Fatalf("init must write allowBypass: true\n%s", orig)
	}
	// allowBypass: false disables the flag (the message names the setting).
	os.WriteFile(global, []byte(strings.Replace(string(orig), "allowBypass: true", "allowBypass: false", 1)), 0o600)
	for _, args := range [][]string{
		{"get", "/k", "--dangerously-bypass-protections"},
		{"decrypt", "--keep-both", "--dangerously-bypass-protections"},
		{"key", "export", "--dangerously-bypass-protections"},
	} {
		r := p.run(args...)
		if r.code != 3 || !strings.Contains(r.stderr, "allowBypass") {
			t.Fatalf("allowBypass false: want exit 3 naming the setting\n%s", r)
		}
		assertNo(t, "refusal", r.out(), "protections-secret")
	}
	r := p.run("run", "--dangerously-bypass-protections", "--", "true")
	if r.code != 125 || !strings.HasPrefix(r.stderr, "[JUREUMA:PROTECTED]") {
		t.Fatalf("run bypass with allowBypass false: want 125 [JUREUMA:PROTECTED]\n%s", r)
	}
	// A hand-edited protections block (seal mismatch) also refuses the bypass.
	os.WriteFile(global, []byte(strings.Replace(string(orig), "agentEnvMarkers: []", "agentEnvMarkers: [SOMETHING]", 1)), 0o600)
	r = p.run("get", "/k", "--dangerously-bypass-protections")
	if r.code != 3 || !strings.Contains(r.stderr, "seal") {
		t.Fatalf("tampered protections: want exit 3\n%s", r)
	}
	// Protections in the project file are rejected outright.
	os.WriteFile(global, orig, 0o600)
	p.expect(0, "get", "/k", "--dangerously-bypass-protections")
	proj := p.read("jureuma.yaml")
	p.write("jureuma.yaml", proj+"protections:\n  allowBypass: true\n")
	if r := p.run("status"); r.code == 0 {
		t.Fatalf("protections in jureuma.yaml must be rejected\n%s", r)
	}
	p.write("jureuma.yaml", proj)
	refusals := 0
	for _, ev := range p.auditEvents() {
		if ev["outcome"] == "bypass-refused" {
			refusals++
		}
	}
	if refusals < 4 {
		t.Fatalf("bypass refusals must be audited (have %d)\n%s", refusals, p.auditLog())
	}
}
