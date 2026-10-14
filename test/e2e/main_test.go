// Package e2e runs the built jureuma binary end to end in throwaway projects.
//
// TestMain builds the binary once into a temporary directory. Every test gets
// its own user home (JUREUMA_USER_HOME and HOME), its own git-initialised
// project directory and a scrubbed environment without agent markers or
// private-key variables, so the real home is never touched.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/CGuiho/jureuma/internal/gate"
)

// testVersion is injected with -ldflags so --version can be checked exactly.
const testVersion = "9.8.7-e2e"

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "jureuma-e2e-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: temp dir:", err)
		os.Exit(1)
	}
	binPath = filepath.Join(dir, "jureuma")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	build := exec.Command("go", "build", "-ldflags", "-X main.version="+testVersion, "-o", binPath, "github.com/CGuiho/jureuma/cmd/jureuma")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: go build failed:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// result is one finished invocation.
type result struct {
	args           []string
	code           int
	stdout, stderr string
}

func (r result) out() string { return r.stdout + r.stderr }

func (r result) String() string {
	return fmt.Sprintf("jureuma %s -> exit %d\n--- stdout ---\n%s--- stderr ---\n%s", strings.Join(r.args, " "), r.code, r.stdout, r.stderr)
}

// project is a temporary user home plus a git-initialised project directory.
type project struct {
	t     *testing.T
	home  string // fake user home (JUREUMA_USER_HOME and HOME)
	dir   string // project root
	env   []string
	trans bytes.Buffer // output of every command run through run()
	nRuns int
}

// scrubbed reports whether an inherited variable must not reach jureuma.
func scrubbed(name string) bool {
	up := strings.ToUpper(name)
	if strings.HasPrefix(up, "JUREUMA_") || strings.HasPrefix(up, "GIT_") {
		return true
	}
	for _, m := range gate.DefaultMarkers {
		if up == m {
			return true
		}
	}
	for _, p := range []string{"CLAUDE", "CODEX", "CURSOR", "GEMINI", "AIDER", "OPENCODE", "AMP_", "CLINE", "GOOSE", "WINDSURF", "COPILOT", "AI_AGENT"} {
		if strings.HasPrefix(up, p) {
			return true
		}
	}
	switch up {
	case "HOME", "USERPROFILE", "XDG_CONFIG_HOME":
		return true
	}
	return false
}

func newProject(t *testing.T) *project {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	p := &project{t: t, home: t.TempDir(), dir: t.TempDir()}
	// Resolve symlinks (macOS /var -> /private/var) so paths compare equal.
	if d, err := filepath.EvalSymlinks(p.dir); err == nil {
		p.dir = d
	}
	if d, err := filepath.EvalSymlinks(p.home); err == nil {
		p.home = d
	}
	for _, kv := range os.Environ() {
		name := kv
		if i := strings.IndexByte(kv, '='); i > 0 {
			name = kv[:i]
		}
		if scrubbed(name) {
			continue
		}
		p.env = append(p.env, kv)
	}
	p.env = append(p.env,
		"HOME="+p.home,
		"USERPROFILE="+p.home,
		"JUREUMA_USER_HOME="+p.home,
		"JUREUMA_NO_UPDATE_CHECK=1",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(p.home, ".gitconfig"),
	)
	p.writeAbs(filepath.Join(p.home, ".gitconfig"), "[user]\n\tname = e2e\n\temail = e2e@example.invalid\n[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n")
	p.git("init", "-q", ".")
	return p
}

// jhome is the CLI home inside the fake user home.
func (p *project) jhome() string { return filepath.Join(p.home, ".guiho", "jureuma") }

func (p *project) path(rel string) string { return filepath.Join(p.dir, filepath.FromSlash(rel)) }

func (p *project) git(args ...string) string {
	p.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = p.dir
	cmd.Env = p.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		p.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// gitOK runs git and reports whether it exited 0.
func (p *project) gitOK(args ...string) bool {
	cmd := exec.Command("git", args...)
	cmd.Dir = p.dir
	cmd.Env = p.env
	return cmd.Run() == nil
}

// exec runs the binary with extra environment entries (NAME=VALUE; an entry
// "NAME" alone removes NAME) and stdin, from dir.
func (p *project) execIn(dir string, extraEnv []string, stdin string, args ...string) result {
	p.t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Dir = dir
	cmd.Env = mergeEnv(p.env, extraEnv)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			p.t.Fatalf("running jureuma %s: %v", strings.Join(args, " "), err)
		}
		code = ee.ExitCode()
	}
	r := result{args: args, code: code, stdout: so.String(), stderr: se.String()}
	p.trans.WriteString(r.stdout)
	p.trans.WriteString(r.stderr)
	p.nRuns++
	return r
}

func mergeEnv(base, extra []string) []string {
	out := append([]string(nil), base...)
	for _, kv := range extra {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		filtered := out[:0:0]
		for _, b := range out {
			if b == name || strings.HasPrefix(b, name+"=") {
				continue
			}
			filtered = append(filtered, b)
		}
		out = filtered
		if strings.Contains(kv, "=") {
			out = append(out, kv)
		}
	}
	return out
}

func (p *project) run(args ...string) result { return p.execIn(p.dir, nil, "", args...) }

func (p *project) runStdin(stdin string, args ...string) result {
	return p.execIn(p.dir, nil, stdin, args...)
}

func (p *project) runEnv(env []string, args ...string) result {
	return p.execIn(p.dir, env, "", args...)
}

// expect runs a command and fails the test unless it exits with code.
func (p *project) expect(code int, args ...string) result {
	p.t.Helper()
	r := p.run(args...)
	if r.code != code {
		p.t.Fatalf("want exit %d\n%s", code, r)
	}
	return r
}

func (p *project) expectStdin(code int, stdin string, args ...string) result {
	p.t.Helper()
	r := p.runStdin(stdin, args...)
	if r.code != code {
		p.t.Fatalf("want exit %d\n%s", code, r)
	}
	return r
}

func (p *project) expectEnv(code int, env []string, args ...string) result {
	p.t.Helper()
	r := p.runEnv(env, args...)
	if r.code != code {
		p.t.Fatalf("want exit %d\n%s", code, r)
	}
	return r
}

func (p *project) writeAbs(path, content string) {
	p.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		p.t.Fatal(err)
	}
}

func (p *project) write(rel, content string) { p.t.Helper(); p.writeAbs(p.path(rel), content) }

func (p *project) read(rel string) string {
	p.t.Helper()
	data, err := os.ReadFile(p.path(rel))
	if err != nil {
		p.t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func (p *project) exists(rel string) bool {
	_, err := os.Stat(p.path(rel))
	return err == nil
}

func (p *project) remove(rel string) {
	p.t.Helper()
	if err := os.Remove(p.path(rel)); err != nil {
		p.t.Fatal(err)
	}
}

func (p *project) auditLog() string {
	data, _ := os.ReadFile(filepath.Join(p.jhome(), "audit.log"))
	return string(data)
}

// auditEvents parses audit.log.
func (p *project) auditEvents() []map[string]any {
	p.t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(p.auditLog()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			p.t.Fatalf("audit line is not JSON: %v", err)
		}
		out = append(out, m)
	}
	return out
}

// initProject runs a non-interactive init.
func (p *project) init(extra ...string) result {
	p.t.Helper()
	return p.expect(0, append([]string{"init", "--agent-deny-rules", "no", "--agent-evolution", "always-ask"}, extra...)...)
}

// setup runs init, writes the plaintext document and encrypts it.
func (p *project) setup(plaintext string) {
	p.t.Helper()
	p.init()
	p.write("config.unencrypted.json", plaintext)
	p.expect(0, "encrypt", "--keep-both")
}

// keyFiles returns the active key files.
func (p *project) keyFiles() []string {
	p.t.Helper()
	m, _ := filepath.Glob(filepath.Join(p.jhome(), "keys", "k_*.json"))
	sort.Strings(m)
	return m
}

// privateKey reads the only active private key (key-file JSON field).
func (p *project) privateKey() (keyID, sk string) {
	p.t.Helper()
	files := p.keyFiles()
	if len(files) != 1 {
		p.t.Fatalf("want one key file, have %d", len(files))
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		p.t.Fatal(err)
	}
	var kf struct {
		KeyID      string `json:"keyId"`
		PrivateKey string `json:"privateKey"`
	}
	if err := json.Unmarshal(data, &kf); err != nil {
		p.t.Fatal(err)
	}
	return kf.KeyID, kf.PrivateKey
}

// hideKeys moves keys/ away (an agent machine) and returns a restore func.
func (p *project) hideKeys() func() {
	p.t.Helper()
	src := filepath.Join(p.jhome(), "keys")
	dst := filepath.Join(p.home, "keys-hidden")
	if err := os.Rename(src, dst); err != nil {
		p.t.Fatal(err)
	}
	return func() {
		p.t.Helper()
		if err := os.Rename(dst, src); err != nil {
			p.t.Fatal(err)
		}
	}
}

// encMeta returns the $jureuma block of the encrypted file.
func (p *project) encMeta(rel string) map[string]any {
	p.t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(p.read(rel)), &m); err != nil {
		p.t.Fatalf("%s: %v", rel, err)
	}
	meta, _ := m["$jureuma"].(map[string]any)
	if meta == nil {
		p.t.Fatalf("%s has no $jureuma block", rel)
	}
	return meta
}

// revealConfig runs the child with the bypass flag and returns the exact
// JUREUMA_CONFIG text the child received.
func (p *project) revealConfig(extra ...string) string {
	p.t.Helper()
	args := append([]string{"run", "--dangerously-bypass-protections"}, extra...)
	args = append(args, "--", "sh", "-c", `printf '%s' "$JUREUMA_CONFIG"`)
	r := p.expect(0, args...)
	return r.stdout
}

// statusJSON parses `status --output json`.
func (p *project) statusJSON(extra ...string) (overall string, states map[string]string) {
	p.t.Helper()
	r := p.expect(0, append([]string{"status", "--output", "json"}, extra...)...)
	var s struct {
		Overall string `json:"overall"`
		Paths   []struct {
			Pointer string `json:"pointer"`
			State   string `json:"state"`
		} `json:"paths"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &s); err != nil {
		p.t.Fatalf("status json: %v\n%s", err, r)
	}
	states = map[string]string{}
	for _, x := range s.Paths {
		states[x.Pointer] = x.State
	}
	return s.Overall, states
}

func needSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs sh")
	}
}

func assertNo(t *testing.T, where, data string, values ...string) {
	t.Helper()
	for _, v := range values {
		if strings.Contains(data, v) {
			t.Fatalf("%s contains a configuration value (%q):\n%s", where, v, data)
		}
	}
}

// stripWS removes all JSON whitespace (only valid for documents whose
// strings contain no whitespace).
func stripWS(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		}
		return r
	}, s)
}
