package pair

import (
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/CGuiho/jureuma/internal/crypt"
	"github.com/CGuiho/jureuma/internal/doc"
	"github.com/CGuiho/jureuma/internal/jsonc"
	"github.com/CGuiho/jureuma/internal/paths"
	"github.com/CGuiho/jureuma/internal/xerr"
)

// MetaKey is the reserved top-level key of an encrypted file.
const MetaKey = "$jureuma"

// FormatVersion is the only encrypted-file format version.
const FormatVersion = 1

// Encrypted is a parsed encrypted file. Body excludes $jureuma.
type Encrypted struct {
	Meta Meta
	Body *doc.Value
}

// Meta is the $jureuma block.
type Meta struct {
	Format           int
	PublicKey, KeyID string
	Schema           string
	Sync             map[string]SyncEntry
	Pending          []string
}

// SyncEntry is the per-leaf baseline: c tags the ciphertext, h the plaintext.
type SyncEntry struct{ C, H string }

// PublicKeyValue parses Meta.PublicKey.
func (m Meta) PublicKeyValue() (crypt.PublicKey, error) {
	return crypt.ParsePublicKey(m.PublicKey)
}

// NewEncrypted returns an empty encrypted file for pk.
func NewEncrypted(pk crypt.PublicKey, schemaRef string) *Encrypted {
	return &Encrypted{
		Meta: Meta{Format: FormatVersion, PublicKey: pk.String(), KeyID: crypt.KeyID(pk), Schema: schemaRef, Sync: map[string]SyncEntry{}},
		Body: doc.NewObject(),
	}
}

var tagRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ErrNotFound is wrapped when a pair file does not exist.
var ErrNotFound = fs.ErrNotExist

// ReadEncrypted parses and checks an encrypted file: format, keyId/publicKey
// consistency (exit 5 on mismatch), sync/pending shape, and that every leaf is
// a ciphertext.
func ReadEncrypted(path string) (*Encrypted, error) {
	name := filepath.Base(path)
	data, err := readLimited(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &xerr.Error{Code: xerr.CodeFailure, Kind: xerr.KindFailure, Msg: name + ": not found (run jureuma encrypt if the configuration is decrypted, or jureuma init)", Err: fs.ErrNotExist}
		}
		return nil, readErr(name, err)
	}
	return ParseEncrypted(name, data)
}

// ParseEncrypted parses encrypted-file content; name is used in error messages.
func ParseEncrypted(name string, data []byte) (*Encrypted, error) {
	root, err := jsonc.Parse(data, true)
	if err != nil {
		return nil, xerr.Failure("%s: %v", name, err)
	}
	if root.Kind != doc.Object {
		return nil, xerr.Failure("%s: top level must be an object", name)
	}
	mv := root.Get(MetaKey)
	if mv == nil || mv.Kind != doc.Object {
		return nil, xerr.Failure("%s: missing %s block", name, MetaKey)
	}
	bad := func(field string) error {
		return xerr.Failure("%s: %s/%s is invalid", name, MetaKey, field)
	}
	e := &Encrypted{Meta: Meta{Sync: map[string]SyncEntry{}}}
	for _, k := range mv.Keys {
		v := mv.M[k]
		switch k {
		case "format":
			if v.Kind != doc.Number || v.N != "1" {
				return nil, xerr.Failure("%s: unsupported %s/format (this jureuma reads format 1)", name, MetaKey)
			}
			e.Meta.Format = FormatVersion
		case "publicKey":
			if v.Kind != doc.String {
				return nil, bad(k)
			}
			e.Meta.PublicKey = v.S
		case "keyId":
			if v.Kind != doc.String || !crypt.ValidKeyID(v.S) {
				return nil, bad(k)
			}
			e.Meta.KeyID = v.S
		case "schema":
			if v.Kind != doc.String {
				return nil, bad(k)
			}
			e.Meta.Schema = v.S
		case "sync":
			if v.Kind != doc.Object {
				return nil, bad(k)
			}
			for _, p := range v.Keys {
				ent := v.M[p]
				if _, err := doc.ParsePointer(p); err != nil || ent.Kind != doc.Object {
					return nil, bad(k)
				}
				c, h := ent.Get("c"), ent.Get("h")
				if c == nil || h == nil || c.Kind != doc.String || h.Kind != doc.String || !tagRe.MatchString(c.S) || !tagRe.MatchString(h.S) || len(ent.Keys) != 2 {
					return nil, bad(k)
				}
				e.Meta.Sync[p] = SyncEntry{C: c.S, H: h.S}
			}
		case "pending":
			if v.Kind != doc.Array {
				return nil, bad(k)
			}
			for _, x := range v.A {
				if x.Kind != doc.String {
					return nil, bad(k)
				}
				if _, err := doc.ParsePointer(x.S); err != nil {
					return nil, bad(k)
				}
				e.Meta.Pending = append(e.Meta.Pending, x.S)
			}
		default:
			return nil, xerr.Failure("%s: unknown field %s/%s", name, MetaKey, k)
		}
	}
	if e.Meta.Format != FormatVersion {
		return nil, bad("format")
	}
	if e.Meta.PublicKey == "" || e.Meta.KeyID == "" {
		return nil, bad("publicKey")
	}
	pk, err := crypt.ParsePublicKey(e.Meta.PublicKey)
	if err != nil {
		return nil, bad("publicKey")
	}
	if crypt.KeyID(pk) != e.Meta.KeyID {
		return nil, xerr.Key("%s: %s/keyId does not match %s/publicKey", name, MetaKey, MetaKey)
	}
	body := doc.NewObject()
	for _, k := range root.Keys {
		if k == MetaKey {
			continue
		}
		body.Put(k, root.M[k])
	}
	for _, l := range doc.Leaves(body) {
		if l.Value.Kind != doc.String || !crypt.IsCiphertext(l.Value.S) {
			return nil, xerr.Failure("%s: %s: value is not a jureuma ciphertext", name, l.Pointer)
		}
	}
	e.Body = body
	return e, nil
}

// MarshalEncrypted renders e with $jureuma first and sorted sync/pending.
func MarshalEncrypted(e *Encrypted) []byte {
	m := doc.NewObject()
	n, _ := doc.NewNumber("1")
	m.Put("format", n)
	m.Put("publicKey", doc.NewString(e.Meta.PublicKey))
	m.Put("keyId", doc.NewString(e.Meta.KeyID))
	if e.Meta.Schema != "" {
		m.Put("schema", doc.NewString(e.Meta.Schema))
	}
	sync := doc.NewObject()
	keys := make([]string, 0, len(e.Meta.Sync))
	for k := range e.Meta.Sync {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ent := doc.NewObject()
		ent.Put("c", doc.NewString(e.Meta.Sync[k].C))
		ent.Put("h", doc.NewString(e.Meta.Sync[k].H))
		sync.Put(k, ent)
	}
	m.Put("sync", sync)
	pending := doc.NewArray()
	for _, p := range SortedUnique(e.Meta.Pending) {
		pending.A = append(pending.A, doc.NewString(p))
	}
	m.Put("pending", pending)
	root := doc.NewObject()
	root.Put(MetaKey, m)
	if e.Body != nil {
		for _, k := range e.Body.Keys {
			if k == MetaKey {
				continue
			}
			root.Put(k, e.Body.M[k])
		}
	}
	return doc.Marshal(root)
}

// WriteEncrypted writes e atomically ($jureuma first, sorted sync/pending).
func WriteEncrypted(path string, e *Encrypted) error {
	if err := CheckEncryptedName(path); err != nil {
		return err
	}
	data := MarshalEncrypted(e)
	if len(data) > maxFileSize {
		return tooLarge(path)
	}
	if err := paths.AtomicWrite(path, data, 0o644); err != nil {
		return xerr.Failure("%s: cannot write file", filepath.Base(path))
	}
	return nil
}

// tooLarge refuses a write that jureuma could not read back.
func tooLarge(path string) error {
	return xerr.Validation("%s: the result would be larger than the %d MiB jureuma can read; nothing was written", filepath.Base(path), maxFileSize>>20)
}

// readErr maps a readLimited failure to a message without content.
func readErr(name string, err error) error {
	if errors.Is(err, errTooLarge) {
		return xerr.Failure("%s: file too large (jureuma reads at most %d MiB)", name, maxFileSize>>20)
	}
	return xerr.Failure("%s: cannot read file", name)
}

// SortedUnique returns a sorted copy of s without duplicates.
func SortedUnique(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	j := 0
	for i, v := range out {
		if i > 0 && v == out[j-1] {
			continue
		}
		out[j] = v
		j++
	}
	return out[:j]
}

// ReadPlain parses an unencrypted file (JSONC when jsonc is true). The top
// level must be an object without the reserved $jureuma key.
func ReadPlain(path string, jsonc_ bool) (*doc.Value, error) {
	name := filepath.Base(path)
	data, err := readLimited(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &xerr.Error{Code: xerr.CodeFailure, Kind: xerr.KindFailure, Msg: name + ": not found", Err: fs.ErrNotExist}
		}
		return nil, readErr(name, err)
	}
	v, err := jsonc.Parse(data, !jsonc_)
	if err != nil {
		return nil, xerr.Validation("%s: %v", name, err)
	}
	if v.Kind != doc.Object {
		return nil, xerr.Validation("%s: top level must be an object", name)
	}
	if v.Get(MetaKey) != nil {
		return nil, xerr.Validation("%s: the top-level key %s is reserved", name, MetaKey)
	}
	return v, nil
}

// WritePlain writes an unencrypted .json file with mode 0600. It refuses
// .jsonc targets, targets that git would not ignore (after adding the managed
// block), and targets tracked by git.
func WritePlain(path string, v *doc.Value) error {
	name := filepath.Base(path)
	if err := CheckUnencryptedName(path); err != nil {
		return err
	}
	if strings.EqualFold(filepath.Ext(path), ".jsonc") {
		return xerr.Failure("%s: jureuma never writes .jsonc files; edit it by hand or switch the pair to .json", name)
	}
	if v.Kind != doc.Object || v.Get(MetaKey) != nil {
		return xerr.Failure("%s: refusing to write an invalid document", name)
	}
	root, err := paths.ProjectRoot(filepath.Dir(path))
	if err != nil {
		return xerr.Failure("%s: cannot resolve the project root", name)
	}
	if err := EnsureIgnored(root, path); err != nil {
		return err
	}
	tracked, err := TrackedByGit(root, path)
	if err != nil {
		return err
	}
	if tracked {
		return xerr.Failure("%s: refusing to write a file that is tracked by git (run git rm --cached %s)", name, name)
	}
	data := doc.Marshal(v)
	defer clear(data)
	if len(data) > maxFileSize {
		return tooLarge(path)
	}
	if err := paths.AtomicWrite(path, data, 0o600); err != nil {
		return xerr.Failure("%s: cannot write file", name)
	}
	return nil
}
