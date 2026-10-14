package pair

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CGuiho/jureuma/internal/doc"
	"github.com/CGuiho/jureuma/internal/jsonc"
	"github.com/CGuiho/jureuma/internal/paths"
	"github.com/CGuiho/jureuma/internal/xerr"
)

// Markers of the managed .gitignore block.
const (
	GitignoreBegin = "# >>> jureuma managed block >>>"
	GitignoreEnd   = "# <<< jureuma managed block <<<"
)

// GitignoreBlockLines is the managed block, markers included.
var GitignoreBlockLines = []string{GitignoreBegin, "*.unencrypted.json", "*.unencrypted.jsonc", GitignoreEnd}

var errNoGit = errors.New("git unavailable")

// git runs git in dir and returns its exit code. errNoGit means git is not
// installed or dir is not inside a work tree.
func git(dir string, args ...string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	err := cmd.Run()
	if err == nil {
		return 0, out.Bytes(), nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), out.Bytes(), nil
	}
	return -1, nil, errNoGit
}

// InGitRepo reports whether dir is inside a git work tree.
func InGitRepo(dir string) bool {
	code, out, err := git(dir, "rev-parse", "--is-inside-work-tree")
	return err == nil && code == 0 && strings.TrimSpace(string(out)) == "true"
}

func existingDir(p string) string {
	for {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		p = parent
	}
}

// HasGitignoreBlock reports whether root/.gitignore contains the complete
// managed block.
func HasGitignoreBlock(root string) bool {
	data, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return false
	}
	return blockRange(splitLines(string(data))) != nil
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

// blockRange returns [begin, end] line indexes of a complete current block.
func blockRange(lines []string) []int {
	for i, l := range lines {
		if strings.TrimSpace(l) != GitignoreBegin {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == GitignoreEnd {
				body := lines[i : j+1]
				if len(body) != len(GitignoreBlockLines) {
					return []int{i, j, 0}
				}
				for k := range body {
					if strings.TrimSpace(body[k]) != GitignoreBlockLines[k] {
						return []int{i, j, 0}
					}
				}
				return []int{i, j, 1}
			}
		}
	}
	return nil
}

// EnsureGitignoreBlock adds (or repairs) the managed block in root/.gitignore,
// keeping every other line. It reports whether the file changed.
func EnsureGitignoreBlock(root string) (bool, error) {
	path := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, xerr.Failure(".gitignore: cannot read file")
	}
	lines := splitLines(string(data))
	r := blockRange(lines)
	if r != nil && r[2] == 1 {
		return false, nil
	}
	var out []string
	if r != nil {
		out = append(out, lines[:r[0]]...)
		out = append(out, GitignoreBlockLines...)
		out = append(out, lines[r[1]+1:]...)
	} else {
		out = append(out, lines...)
		if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		out = append(out, GitignoreBlockLines...)
	}
	text := strings.Join(out, "\n") + "\n"
	if strings.Contains(string(data), "\r\n") {
		text = strings.ReplaceAll(text, "\n", "\r\n")
	}
	if err := paths.AtomicWrite(path, []byte(text), 0o644); err != nil {
		return false, xerr.Failure(".gitignore: cannot write file")
	}
	return true, nil
}

// IgnoredByGit reports whether git would ignore path. ok is false when git is
// unavailable or the path is not inside a work tree.
func IgnoredByGit(path string) (ignored, ok bool) {
	dir := existingDir(filepath.Dir(path))
	if !InGitRepo(dir) {
		return false, false
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false, false
	}
	code, _, err := git(dir, "check-ignore", "--no-index", "-q", "--", filepath.ToSlash(rel))
	if err != nil || (code != 0 && code != 1) {
		return false, false
	}
	return code == 0, true
}

// EnsureIgnored makes sure git ignores path: when it would not be ignored it
// adds the managed block to root/.gitignore and checks again; if it is still
// not ignored (for example because of a negation rule) it returns an error.
// Outside a git work tree it only ensures the block exists.
func EnsureIgnored(root, path string) error {
	ignored, ok := IgnoredByGit(path)
	if ok && ignored {
		return nil
	}
	if _, err := EnsureGitignoreBlock(root); err != nil {
		return err
	}
	if !ok {
		return nil
	}
	ignored, ok = IgnoredByGit(path)
	if ok && !ignored {
		return xerr.Failure("%s: refusing to write: git does not ignore it (check .gitignore negation rules)", filepath.Base(path))
	}
	return nil
}

// TrackedByGit reports whether path is tracked by git. Outside a work tree it
// returns false.
func TrackedByGit(root, path string) (bool, error) {
	dir := existingDir(filepath.Dir(path))
	if !InGitRepo(dir) {
		return false, nil
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false, nil
	}
	code, _, err := git(dir, "ls-files", "--error-unmatch", "--", filepath.ToSlash(rel))
	if err != nil {
		return false, nil
	}
	return code == 0, nil
}

// HeadPublicKey returns $jureuma.publicKey of path as committed at git HEAD.
// ok is false when the file is not in HEAD or git is unavailable.
func HeadPublicKey(path string) (pk string, ok bool) {
	dir := existingDir(filepath.Dir(path))
	if !InGitRepo(dir) {
		return "", false
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return "", false
	}
	code, out, err := git(dir, "show", "HEAD:./"+filepath.ToSlash(rel))
	if err != nil || code != 0 {
		return "", false
	}
	v, err := jsonc.Parse(out, true)
	if err != nil {
		return "", false
	}
	m := v.Get(MetaKey)
	if m == nil {
		return "", false
	}
	p := m.Get("publicKey")
	if p == nil || p.Kind != doc.String {
		return "", false
	}
	return p.S, true
}

// CommittedContent returns the content of path at git HEAD, or false when
// git is unavailable or the file is not committed.
func CommittedContent(path string) ([]byte, bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, false
	}
	dir := filepath.Dir(abs)
	code, top, err := git(dir, "rev-parse", "--show-toplevel")
	if err != nil || code != 0 {
		return nil, false
	}
	rel, err := filepath.Rel(strings.TrimSpace(string(top)), abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, false
	}
	code, out, err := git(dir, "show", "HEAD:"+filepath.ToSlash(rel))
	if err != nil || code != 0 {
		return nil, false
	}
	return out, true
}
