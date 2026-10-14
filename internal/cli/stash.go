package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/CGuiho/jureuma/internal/pair"
	"github.com/CGuiho/jureuma/internal/paths"
)

// When decrypt removes the encrypted file, a copy of it (ciphertext and
// metadata only) is kept under the CLI home so the next encrypt reuses the same
// key, sync baseline and unchanged ciphertexts.

func stashPath(home, encryptedPath string) string {
	abs, err := filepath.Abs(encryptedPath)
	if err != nil {
		abs = encryptedPath
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(home, "state", "stash", hex.EncodeToString(sum[:8])+".encrypted.json")
}

func saveStash(home, encryptedPath string, e *pair.Encrypted) error {
	return paths.AtomicWrite(stashPath(home, encryptedPath), pair.MarshalEncrypted(e), 0o600)
}

func dropStash(home, encryptedPath string) {
	_ = os.Remove(stashPath(home, encryptedPath))
}

// readEncryptedOrStash reads the encrypted file. When it is missing it falls
// back to the stash written by decrypt, then to the version at git HEAD.
// fromStash reports that the file itself was absent.
func readEncryptedOrStash(home string, p *pair.Pair) (enc *pair.Encrypted, fromStash bool, err error) {
	enc, err = pair.ReadEncrypted(p.EncryptedPath)
	if err == nil || fileExists(p.EncryptedPath) {
		return enc, false, err
	}
	name := filepath.Base(p.EncryptedPath)
	if data, rerr := os.ReadFile(stashPath(home, p.EncryptedPath)); rerr == nil {
		if e, perr := pair.ParseEncrypted(name+" (saved copy)", data); perr == nil {
			return e, true, nil
		}
	}
	if data, ok := pair.CommittedContent(p.EncryptedPath); ok {
		if e, perr := pair.ParseEncrypted(name+" (git HEAD)", data); perr == nil {
			return e, true, nil
		}
	}
	return nil, false, err
}
