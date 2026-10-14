package cli

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/CGuiho/jureuma/internal/crypt"
	"github.com/CGuiho/jureuma/internal/doc"
	"github.com/CGuiho/jureuma/internal/jsonc"
	"github.com/CGuiho/jureuma/internal/pair"
	"github.com/CGuiho/jureuma/internal/schema"
	"github.com/CGuiho/jureuma/internal/xerr"
	"github.com/spf13/cobra"
)

const maxValueSize = 16 << 20

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ---- encrypt ----

func (a *app) cmdEncrypt() *cobra.Command {
	var pf pairFlags
	var force, keepBoth bool
	c := &cobra.Command{
		Use:   "encrypt",
		Short: "encrypt the unencrypted file into the encrypted file",
		Long: `Validates the whole unencrypted document against the schema, then encrypts every value
into the encrypted file. Unchanged values keep their ciphertext so diffs stay small; values
under a retired key are migrated. Refuses to overwrite paths changed on the encrypted side
(encrypted-newer or conflict) unless --force is given. --force resolves conflicts in favour
of the unencrypted file; paths changed only on the encrypted side are kept and stay pending.
On success the unencrypted file is deleted unless --keep-both is given. When the encrypted
file is missing (removed by decrypt), its saved copy or the version at git HEAD supplies the
key and unchanged ciphertexts. Needs the private key.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			p, err := e.resolve(&pf)
			if err != nil {
				return err
			}
			if err := p.CheckSchemaFlag(); err != nil {
				return err
			}
			unlock, err := e.lock(p)
			if err != nil {
				return err
			}
			defer unlock()
			enc, restored, err := readEncryptedOrStash(e.home, p)
			if err != nil {
				return err
			}
			sk, err := e.requireKey(enc)
			if err != nil {
				return err
			}
			if !fileExists(p.UnencryptedPath) {
				return xerr.Failure("%s: not found; nothing to encrypt", p.Rel(p.UnencryptedPath))
			}
			plain, err := pair.ReadPlain(p.UnencryptedPath, p.UnencryptedIsJSONC)
			if err != nil {
				return err
			}
			sch, err := loadSchema(p)
			if err != nil {
				return err
			}
			if sch != nil {
				if issues := sch.Validate(plain); len(issues) > 0 {
					return issuesErr(cmd, p.Rel(p.UnencryptedPath), issues)
				}
			}
			rep := pair.Status(p, enc, plain, &sk)
			// --force overrides conflicts only. Paths changed on the encrypted
			// side alone (an agent's set or unset) are kept as they are and
			// stay pending, so --force never drops them silently.
			var encNewer []string
			if force {
				encNewer = rep.Pointers(pair.StateEncryptedNewer)
			}
			if !force {
				var blocked []string
				for _, ps := range rep.Paths {
					if ps.State == pair.StateConflict || ps.State == pair.StateEncryptedNewer {
						blocked = append(blocked, ps.Pointer+" ("+ps.State+")")
					}
				}
				if len(blocked) > 0 {
					for _, b := range blocked {
						errf(cmd, "  %s\n", b)
					}
					return xerr.Failure("refusing to overwrite %d %s changed on the encrypted side; run jureuma decrypt first, or pass --force", len(blocked), plural(len(blocked), "path", "paths"))
				}
			}
			pk := sk.Public()
			body, err := pair.EncryptDoc(pk, plain, enc, &sk)
			if err != nil {
				return err
			}
			next := &pair.Encrypted{Meta: enc.Meta, Body: body}
			next.Meta.PublicKey = pk.String()
			next.Meta.KeyID = crypt.KeyID(pk)
			next.Meta.Sync = pair.ComputeSync(sk, plain, body)
			next.Meta.Pending = nil
			if len(encNewer) > 0 {
				kept, dropped := keepEncryptedSide(enc, body, encNewer)
				for _, ptr := range kept {
					if base, ok := enc.Meta.Sync[ptr]; ok {
						next.Meta.Sync[ptr] = base
					} else {
						delete(next.Meta.Sync, ptr)
					}
				}
				next.Meta.Pending = kept
				if len(kept) > 0 {
					errf(cmd, "kept %d encrypted-side %s (still pending; run jureuma decrypt to bring %s into %s):\n", len(kept), plural(len(kept), "change", "changes"), plural(len(kept), "it", "them"), p.Rel(p.UnencryptedPath))
					for _, ptr := range kept {
						errf(cmd, "  %s\n", ptr)
					}
				}
				if len(dropped) > 0 {
					errf(cmd, "warning: --force discarded %d encrypted-side %s that no longer fit the unencrypted document:\n", len(dropped), plural(len(dropped), "change", "changes"))
					for _, ptr := range dropped {
						errf(cmd, "  %s\n", ptr)
					}
				}
			}
			oldLeaves := pair.LeafMap(enc.Body)
			reused, total := 0, 0
			for _, l := range doc.Leaves(body) {
				total++
				if o, ok := oldLeaves[l.Pointer]; ok && o.S == l.Value.S {
					reused++
				}
			}
			if !restored && bytes.Equal(pair.MarshalEncrypted(next), pair.MarshalEncrypted(enc)) {
				outf(cmd, "%s is already up to date (%d %s)\n", p.Rel(p.EncryptedPath), total, plural(total, "value", "values"))
			} else {
				if err := pair.WriteEncrypted(p.EncryptedPath, next); err != nil {
					return err
				}
				outf(cmd, "encrypted %d %s into %s (%d unchanged, %d newly encrypted)\n", total, plural(total, "value", "values"), p.Rel(p.EncryptedPath), reused, total-reused)
			}
			dropStash(e.home, p.EncryptedPath)
			if !keepBoth {
				if err := os.Remove(p.UnencryptedPath); err != nil {
					return xerr.Failure("%s: encrypted, but the unencrypted file could not be removed", p.Rel(p.UnencryptedPath))
				}
				outf(cmd, "removed %s (pass --keep-both to keep it)\n", p.Rel(p.UnencryptedPath))
			}
			return nil
		},
	}
	addPairFlags(c, &pf)
	c.Flags().BoolVar(&force, "force", false, "overwrite paths in conflict (paths changed only on the encrypted side are kept and stay pending)")
	c.Flags().BoolVar(&keepBoth, "keep-both", false, "keep the unencrypted file instead of deleting it")
	return c
}

// keepEncryptedSide copies the encrypted-side state of each pointer in ptrs
// from enc into body (the newly encrypted document): an existing ciphertext
// is kept as is (it is bound to that pointer), a removed leaf stays removed.
// Pointers that cannot be kept without shifting other array elements or
// passing through a scalar are returned as dropped.
func keepEncryptedSide(enc *pair.Encrypted, body *doc.Value, ptrs []string) (kept, dropped []string) {
	old := pair.LeafMap(enc.Body)
	for _, ptr := range ptrs {
		toks, err := doc.ParsePointer(ptr)
		if err != nil || len(toks) == 0 {
			dropped = append(dropped, ptr)
			continue
		}
		if ct, ok := old[ptr]; ok {
			if err := doc.SetAt(body, toks, ct.Clone()); err != nil {
				dropped = append(dropped, ptr)
				continue
			}
			kept = append(kept, ptr)
			continue
		}
		parent, err := doc.Lookup(body, toks[:len(toks)-1])
		if err != nil {
			kept = append(kept, ptr) // already absent
			continue
		}
		last := toks[len(toks)-1]
		switch parent.Kind {
		case doc.Object:
			parent.Remove(last)
			kept = append(kept, ptr)
		case doc.Array:
			idx, err := strconv.Atoi(last)
			switch {
			case err != nil || idx >= len(parent.A):
				kept = append(kept, ptr)
			case idx == len(parent.A)-1:
				parent.A = parent.A[:idx]
				kept = append(kept, ptr)
			default:
				dropped = append(dropped, ptr)
			}
		default:
			dropped = append(dropped, ptr)
		}
	}
	return pair.SortedUnique(kept), pair.SortedUnique(dropped)
}

// ---- decrypt ----

func (a *app) cmdDecrypt() *cobra.Command {
	var pf pairFlags
	var force, bypass, keepBoth bool
	c := &cobra.Command{
		Use:   "decrypt",
		Short: "[human-only] decrypt the encrypted file into the unencrypted file",
		Long: `Writes every decrypted value into the unencrypted .json file (mode 0600, git-ignored).
Human-only: requires an interactive terminal, no agent environment and a typed confirmation
word. Refuses when the unencrypted file has unsaved edits (unencrypted-newer or conflict)
unless --force is given. Never writes .jsonc files. On success the encrypted file is deleted
unless --keep-both is given; a copy (ciphertext only) is saved under ~/.guiho/jureuma/state so
the next jureuma encrypt reuses the same key and unchanged ciphertexts.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := loadEnv()
			if err != nil {
				return err
			}
			p, err := e.resolve(&pf)
			if err != nil {
				return err
			}
			if err := p.CheckSchemaFlag(); err != nil {
				return err
			}
			if p.UnencryptedIsJSONC {
				return xerr.Failure("%s: jureuma never writes .jsonc files; edit it by hand or switch the pair to .json", p.Rel(p.UnencryptedPath))
			}
			unlock, err := e.lock(p)
			if err != nil {
				return err
			}
			defer unlock()
			enc, err := pair.ReadEncrypted(p.EncryptedPath)
			if err != nil {
				return err
			}
			n := len(doc.Leaves(enc.Body))
			files := []string{p.Rel(p.EncryptedPath), p.Rel(p.UnencryptedPath)}
			if err := e.protect(cmd, "decrypt "+itoa(n)+" "+plural(n, "value", "values")+" into "+p.Rel(p.UnencryptedPath), files, bypass); err != nil {
				return err
			}
			sk, err := e.requireKey(enc)
			if err != nil {
				return err
			}
			old, err := readPlainIfExists(p)
			if err != nil {
				return err
			}
			if old != nil && !force {
				rep := pair.Status(p, enc, old, &sk)
				var blocked []string
				for _, ps := range rep.Paths {
					if ps.State == pair.StateConflict || ps.State == pair.StateUnencryptedNewer {
						blocked = append(blocked, ps.Pointer+" ("+ps.State+")")
					}
				}
				for _, ptr := range pair.EmptyContainersOnlyIn(old, enc.Body) {
					blocked = append(blocked, ptr+" ("+pair.StateUnencryptedNewer+", empty container)")
				}
				if len(blocked) > 0 {
					for _, b := range blocked {
						errf(cmd, "  %s\n", b)
					}
					return xerr.Failure("refusing to overwrite %d unsaved %s in %s; run jureuma encrypt first, or pass --force", len(blocked), plural(len(blocked), "edit", "edits"), p.Rel(p.UnencryptedPath))
				}
			}
			plain, err := pair.DecryptDocKeys(pair.StoreKeys(&sk, e.store), enc.Body)
			if err != nil {
				return err
			}
			if err := pair.WritePlain(p.UnencryptedPath, plain); err != nil {
				return err
			}
			next := &pair.Encrypted{Meta: enc.Meta, Body: enc.Body}
			next.Meta.Sync = pair.ComputeSync(sk, plain, enc.Body)
			next.Meta.Pending = nil
			outf(cmd, "decrypted %d %s into %s\n", n, plural(n, "value", "values"), p.Rel(p.UnencryptedPath))
			if keepBoth {
				if !bytes.Equal(pair.MarshalEncrypted(next), pair.MarshalEncrypted(enc)) {
					if err := pair.WriteEncrypted(p.EncryptedPath, next); err != nil {
						return err
					}
				}
				return nil
			}
			if err := saveStash(e.home, p.EncryptedPath, next); err != nil {
				return xerr.Failure("decrypted, but could not save a copy of %s; it was kept", p.Rel(p.EncryptedPath))
			}
			if err := os.Remove(p.EncryptedPath); err != nil {
				return xerr.Failure("decrypted, but %s could not be removed", p.Rel(p.EncryptedPath))
			}
			outf(cmd, "removed %s (run jureuma encrypt to recreate it, or pass --keep-both to keep it)\n", p.Rel(p.EncryptedPath))
			return nil
		},
	}
	addPairFlags(c, &pf)
	c.Flags().BoolVar(&force, "force", false, "overwrite unsaved edits in the unencrypted file")
	c.Flags().BoolVar(&keepBoth, "keep-both", false, "keep the encrypted file instead of deleting it")
	addBypassFlag(c, &bypass, "skip the human-only gate (only when a human explicitly asked; audited)")
	return c
}

// ---- set ----

func readValue(cmd *cobra.Command, args []string, fromStdin bool, fromFile string) ([]byte, error) {
	sources := 0
	if len(args) > 1 {
		sources++
	}
	if fromStdin {
		sources++
	}
	if fromFile != "" {
		sources++
	}
	if sources != 1 {
		return nil, xerr.Usage("give the value exactly once: as an argument, with --value-stdin, or with --value-file")
	}
	if len(args) > 1 {
		return []byte(args[1]), nil
	}
	var r io.Reader
	if fromStdin {
		r = cmd.InOrStdin()
	} else {
		f, err := os.Open(fromFile)
		if err != nil {
			return nil, xerr.Failure("--value-file: cannot open %s", fromFile)
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxValueSize+1))
	if err != nil {
		return nil, xerr.Failure("cannot read the value")
	}
	if len(data) > maxValueSize {
		return nil, xerr.Validation("the value is larger than 16 MiB")
	}
	// Drop exactly one trailing line break (echo / here-strings add one).
	if bytes.HasSuffix(data, []byte("\r\n")) {
		data = data[:len(data)-2]
	} else if bytes.HasSuffix(data, []byte("\n")) {
		data = data[:len(data)-1]
	}
	return data, nil
}

func parsePointerArg(s string) ([]string, error) {
	toks, err := doc.ParsePointer(s)
	if err != nil {
		// The argument is not echoed: a value passed in the pointer position
		// (arguments swapped) must not be displayed.
		return nil, xerr.Usage("the first argument is not a JSON Pointer (example: /database/url); a pointer starts with /")
	}
	if len(toks) == 0 {
		return nil, xerr.Usage("the root cannot be addressed; use a pointer such as /database/url")
	}
	if toks[0] == pair.MetaKey {
		return nil, xerr.Usage("/%s is reserved", pair.MetaKey)
	}
	if len(toks) > pair.MaxPointerDepth {
		return nil, xerr.Usage("the pointer is deeper than %d levels", pair.MaxPointerDepth)
	}
	return toks, nil
}

func diffIssues(before, after []schema.Issue) []schema.Issue {
	seen := map[string]bool{}
	for _, i := range before {
		seen[i.Pointer+"\x00"+i.Keyword+"\x00"+i.Message] = true
	}
	var out []schema.Issue
	for _, i := range after {
		if !seen[i.Pointer+"\x00"+i.Keyword+"\x00"+i.Message] {
			out = append(out, i)
		}
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// refreshSync marks pointers as synced when both sides now hold the same
// value (or both lack it); otherwise they stay pending.
func refreshSync(enc *pair.Encrypted, sk crypt.PrivateKey, plain *doc.Value, pointers []string) {
	encLeaves := pair.LeafMap(enc.Body)
	plainLeaves := pair.LeafMap(plain)
	done := map[string]bool{}
	for _, p := range pointers {
		ct, inEnc := encLeaves[p]
		pv, inPlain := plainLeaves[p]
		switch {
		case !inEnc && !inPlain:
			delete(enc.Meta.Sync, p)
			done[p] = true
		case inEnc && inPlain:
			dec, err := crypt.DecryptValue(sk, p, ct.S)
			if err != nil {
				continue
			}
			canon := doc.Canonical(pv)
			if bytes.Equal(dec, canon) {
				enc.Meta.Sync[p] = pair.SyncEntry{C: crypt.SyncTag(ct.S), H: crypt.PlainTag(sk, canon)}
				done[p] = true
			}
			clear(dec)
		}
	}
	var pending []string
	for _, p := range enc.Meta.Pending {
		if !done[p] {
			pending = append(pending, p)
		}
	}
	enc.Meta.Pending = pending
}

func (a *app) cmdSet() *cobra.Command {
	var pf pairFlags
	var asJSON, fromStdin, allowInvalid bool
	var fromFile string
	c := &cobra.Command{
		Use:   "set <pointer> [value]",
		Short: "encrypt one value into the encrypted file (works without the private key)",
		Long: `Encrypts one value at a JSON Pointer using the public key in the encrypted file, records
the path as pending, and mirrors the value into an existing .json unencrypted file. The
value is never echoed. By default it is stored as a string; --json parses it as JSON
(numbers, booleans, null, objects, arrays). Prefer --value-stdin so the value stays out of
shell history; one trailing line break is dropped from stdin and --value-file input.`,
		Example: `  printf '%s' "$DATABASE_URL" | jureuma set /database/url --value-stdin
  jureuma set /database/pool --json 20
  jureuma set /features/- --json '{"name":"beta","enabled":true}'`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			toks, err := parsePointerArg(args[0])
			if err != nil {
				return err
			}
			raw, err := readValue(cmd, args, fromStdin, fromFile)
			if err != nil {
				return err
			}
			var val *doc.Value
			if asJSON {
				v, err := jsonc.Parse(raw, true)
				clear(raw)
				if err != nil {
					return xerr.Validation("the value is not valid JSON (%v)", err)
				}
				val = v
			} else {
				if !utf8.Valid(raw) {
					return xerr.Validation("the value is not valid UTF-8")
				}
				if bytes.IndexByte(raw, 0) >= 0 {
					return xerr.Validation("the value contains NUL")
				}
				val = doc.NewString(string(raw))
				clear(raw)
			}
			e, err := loadEnv()
			if err != nil {
				return err
			}
			p, err := e.resolve(&pf)
			if err != nil {
				return err
			}
			if err := p.CheckSchemaFlag(); err != nil {
				return err
			}
			unlock, err := e.lock(p)
			if err != nil {
				return err
			}
			defer unlock()
			enc, err := pair.ReadEncrypted(p.EncryptedPath)
			if err != nil {
				return err
			}
			pk, err := enc.Meta.PublicKeyValue()
			if err != nil {
				return xerr.Failure("invalid $jureuma.publicKey")
			}
			sk, _, err := e.findKey(enc.Meta.KeyID)
			if err != nil {
				return err
			}
			if sk != nil && sk.Public() != pk {
				return xerr.Key("the local private key for %s does not match $jureuma.publicKey", enc.Meta.KeyID)
			}
			sch, err := loadSchema(p)
			if err != nil {
				return err
			}
			concrete := pair.ConcreteTokens(enc.Body, toks)
			if pair.AppendWithoutArray(enc.Body, toks) {
				return xerr.Usage("'-' appends to an existing array only; create the array first (for example jureuma set /list --json '[]')")
			}
			ptr := doc.FormatPointer(concrete)
			var issues []schema.Issue
			if sch != nil {
				if !asJSON {
					if types := sch.ExpectedTypes(ptr); len(types) > 0 && !containsStr(types, "string") && !allowInvalid {
						return xerr.Validation("%s: the schema expects %s, not a string; pass --json to store a non-string value", ptr, strings.Join(types, " or "))
					}
				}
				issues = append(issues, sch.ValidateValue(ptr, val)...)
			}
			encVal, err := pair.EncryptAt(pk, ptr, val)
			if err != nil {
				return err
			}
			removed := pair.LeafPointersUnder(enc.Body, concrete)
			next := &pair.Encrypted{Meta: enc.Meta, Body: enc.Body.Clone()}
			if err := doc.SetAt(next.Body, concrete, encVal); err != nil {
				return xerr.Usage("%v", err)
			}
			if sch != nil {
				issues = append(issues, diffIssues(sch.ValidateStructure(enc.Body), sch.ValidateStructure(next.Body))...)
			}
			if len(issues) > 0 && !allowInvalid {
				for _, is := range issues {
					errf(cmd, "  %s\n", is.String())
				}
				return xerr.Validation("%s: %d validation issue(s); nothing was written (use --allow-invalid to write anyway)", ptr, len(issues))
			}
			added := pair.LeafPointersUnder(next.Body, concrete)
			touched := append(append([]string{}, removed...), added...)
			if len(added) == 0 {
				touched = append(touched, ptr)
			}
			next.Meta.Sync = copySync(enc.Meta.Sync)
			next.Meta.Pending = pair.SortedUnique(append(append([]string{}, enc.Meta.Pending...), touched...))
			if err := pair.WriteEncrypted(p.EncryptedPath, next); err != nil {
				return err
			}
			mirrored, merr := mirrorPlain(p, func(plain *doc.Value) error {
				if reason := mirrorBlocked(p, enc, sk, plain, concrete, toks, touched); reason != "" {
					return &skipMirror{reason: reason}
				}
				return doc.SetAt(plain, concrete, val.Clone())
			})
			if merr != nil {
				errf(cmd, "warning: %s was not updated: %v\n", p.Rel(p.UnencryptedPath), merr)
			}
			if mirrored != nil && sk != nil {
				refreshSync(next, *sk, mirrored, touched)
				if err := pair.WriteEncrypted(p.EncryptedPath, next); err != nil {
					return err
				}
			}
			msg := "set " + ptr + " in " + p.Rel(p.EncryptedPath)
			if mirrored != nil {
				msg += " and " + p.Rel(p.UnencryptedPath)
			}
			if len(issues) > 0 {
				msg += " (with " + itoa(len(issues)) + " validation issue(s), --allow-invalid)"
			}
			outf(cmd, "%s\n", msg)
			return nil
		},
	}
	addPairFlags(c, &pf)
	f := c.Flags()
	f.BoolVar(&asJSON, "json", false, "parse the value as JSON instead of storing a string")
	f.BoolVar(&fromStdin, "value-stdin", false, "read the value from standard input (recommended)")
	f.StringVar(&fromFile, "value-file", "", "read the value from a file")
	f.BoolVar(&allowInvalid, "allow-invalid", false, "write even when schema validation fails")
	return c
}

// skipMirror reports that set left the unencrypted file alone on purpose.
type skipMirror struct{ reason string }

func (e *skipMirror) Error() string {
	return e.reason + "; the value stays pending (jureuma status shows it), reconcile with jureuma decrypt or encrypt"
}

// mirrorBlocked returns why set must not copy its value into plain (the
// unencrypted document as it is on disk), or "" when mirroring is safe. The
// mirror must never replace a human's unsaved edit: with the private key,
// any touched path that is unencrypted-newer or in conflict blocks it;
// without the key, an existing plaintext value at or under the target cannot
// be compared, so it blocks too. An append ('-') also requires both sides'
// arrays to have the same length.
func mirrorBlocked(p *pair.Pair, enc *pair.Encrypted, sk *crypt.PrivateKey, plain *doc.Value, concrete, toks []string, touched []string) string {
	for i, t := range toks {
		if t != "-" || i >= len(concrete) || concrete[i] == "-" {
			continue
		}
		ea, err1 := doc.Lookup(enc.Body, concrete[:i])
		pa, err2 := doc.Lookup(plain, concrete[:i])
		if err1 == nil && err2 == nil && (pa.Kind != doc.Array || len(pa.A) != len(ea.A)) {
			return "the array at " + doc.FormatPointer(concrete[:i]) + " differs between the two files"
		}
	}
	under := pair.LeafPointersUnder(plain, concrete)
	if sk == nil {
		if len(under) > 0 {
			return "it already holds a value at " + doc.FormatPointer(concrete) + " that cannot be checked without the private key"
		}
		return ""
	}
	check := map[string]bool{}
	for _, x := range append(append([]string{}, touched...), under...) {
		check[x] = true
	}
	rep := pair.Status(p, enc, plain, sk)
	for _, ps := range rep.Paths {
		if !check[ps.Pointer] && !strings.HasPrefix(ps.Pointer, doc.FormatPointer(concrete)+"/") && ps.Pointer != doc.FormatPointer(concrete) {
			continue
		}
		if ps.State == pair.StateUnencryptedNewer || ps.State == pair.StateConflict {
			return "it has an unsaved edit at " + ps.Pointer + " (" + ps.State + ")"
		}
	}
	return ""
}

func copySync(m map[string]pair.SyncEntry) map[string]pair.SyncEntry {
	out := make(map[string]pair.SyncEntry, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// mirrorPlain applies fn to an existing .json unencrypted file and writes it.
// It returns the written document, or nil when there was nothing to mirror.
func mirrorPlain(p *pair.Pair, fn func(*doc.Value) error) (*doc.Value, error) {
	if p.UnencryptedIsJSONC || !fileExists(p.UnencryptedPath) {
		return nil, nil
	}
	plain, err := pair.ReadPlain(p.UnencryptedPath, false)
	if err != nil {
		return nil, err
	}
	if err := fn(plain); err != nil {
		return nil, err
	}
	if err := pair.WritePlain(p.UnencryptedPath, plain); err != nil {
		return nil, err
	}
	return plain, nil
}

// ---- unset ----

func (a *app) cmdUnset() *cobra.Command {
	var pf pairFlags
	var allowInvalid bool
	c := &cobra.Command{
		Use:   "unset <pointer>",
		Short: "remove one value (or subtree) from the encrypted file",
		Long: `Removes the value at a JSON Pointer; on a container the whole subtree. Parents are kept.
Without the private key only object members and the last array element can be removed,
because removing another element shifts later indices and their ciphertexts are bound to
their paths. The removal is mirrored into an existing .json unencrypted file. Removing a
required property needs --allow-invalid.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			toks, err := parsePointerArg(args[0])
			if err != nil {
				return err
			}
			for _, t := range toks {
				if t == "-" {
					return xerr.Usage("'-' cannot be used with unset")
				}
			}
			e, err := loadEnv()
			if err != nil {
				return err
			}
			p, err := e.resolve(&pf)
			if err != nil {
				return err
			}
			if err := p.CheckSchemaFlag(); err != nil {
				return err
			}
			unlock, err := e.lock(p)
			if err != nil {
				return err
			}
			defer unlock()
			enc, err := pair.ReadEncrypted(p.EncryptedPath)
			if err != nil {
				return err
			}
			ptr := doc.FormatPointer(toks)
			if _, err := doc.Lookup(enc.Body, toks); err != nil {
				return xerr.Failure("%s: not found in %s", ptr, p.Rel(p.EncryptedPath))
			}
			pk, err := enc.Meta.PublicKeyValue()
			if err != nil {
				return xerr.Failure("invalid $jureuma.publicKey")
			}
			sk, _, err := e.findKey(enc.Meta.KeyID)
			if err != nil {
				return err
			}
			if sk != nil && sk.Public() != pk {
				return xerr.Key("the local private key for %s does not match $jureuma.publicKey", enc.Meta.KeyID)
			}
			parentToks := toks[:len(toks)-1]
			parent, _ := doc.Lookup(enc.Body, parentToks)
			touched := pair.LeafPointersUnder(enc.Body, toks)
			if len(touched) == 0 {
				touched = []string{ptr}
			}
			next := &pair.Encrypted{Meta: enc.Meta, Body: enc.Body.Clone()}
			shift := false
			idx := 0
			if parent != nil && parent.Kind == doc.Array {
				idx = atoiSafe(toks[len(toks)-1])
				shift = idx < len(parent.A)-1
			}
			if shift {
				if sk == nil {
					return xerr.Key("removing %s shifts the array elements after it, which must be re-encrypted with the private key (not available); edit the unencrypted file and run jureuma encrypt instead", ptr)
				}
				// Old leaf pointers of the shifted tail are touched too.
				for i := idx + 1; i < len(parent.A); i++ {
					touched = append(touched, pair.LeafPointersUnder(enc.Body, append(append([]string{}, parentToks...), itoa(i)))...)
				}
			}
			if err := doc.DeleteAt(next.Body, toks); err != nil {
				return xerr.Usage("%v", err)
			}
			if shift {
				arr, _ := doc.Lookup(next.Body, parentToks)
				keys := pair.StoreKeys(sk, e.store)
				parentPtr := doc.FormatPointer(parentToks)
				for i := idx; i < len(arr.A); i++ {
					oldPtr := parentPtr + "/" + itoa(i+1)
					newPtr := parentPtr + "/" + itoa(i)
					dec, err := pair.DecryptAt(keys, oldPtr, arr.A[i])
					if err != nil {
						return err
					}
					reenc, err := pair.EncryptAt(pk, newPtr, dec)
					if err != nil {
						return err
					}
					arr.A[i] = reenc
				}
			}
			sch, err := loadSchema(p)
			if err != nil {
				return err
			}
			if sch != nil {
				issues := diffIssues(sch.ValidateStructure(enc.Body), sch.ValidateStructure(next.Body))
				if len(issues) > 0 && !allowInvalid {
					for _, is := range issues {
						errf(cmd, "  %s\n", is.String())
					}
					return xerr.Validation("%s: %d validation issue(s); nothing was written (use --allow-invalid to write anyway)", ptr, len(issues))
				}
			}
			next.Meta.Sync = copySync(enc.Meta.Sync)
			next.Meta.Pending = pair.SortedUnique(append(append([]string{}, enc.Meta.Pending...), touched...))
			if err := pair.WriteEncrypted(p.EncryptedPath, next); err != nil {
				return err
			}
			mirrored, merr := mirrorPlain(p, func(plain *doc.Value) error {
				if _, err := doc.Lookup(plain, toks); err != nil {
					return nil
				}
				return doc.DeleteAt(plain, toks)
			})
			if merr != nil {
				errf(cmd, "warning: %s was not updated: %v\n", p.Rel(p.UnencryptedPath), merr)
			}
			if mirrored != nil && sk != nil {
				refreshSync(next, *sk, mirrored, touched)
				if err := pair.WriteEncrypted(p.EncryptedPath, next); err != nil {
					return err
				}
			}
			outf(cmd, "removed %s from %s\n", ptr, p.Rel(p.EncryptedPath))
			return nil
		},
	}
	addPairFlags(c, &pf)
	c.Flags().BoolVar(&allowInvalid, "allow-invalid", false, "write even when schema validation fails")
	return c
}

// ---- get ----

func (a *app) cmdGet() *cobra.Command {
	var pf pairFlags
	var bypass, asJSON bool
	c := &cobra.Command{
		Use:   "get <pointer>",
		Short: "[human-only] print one plaintext value",
		Long: `Decrypts and prints the value at a JSON Pointer. Strings are printed raw unless --json is
given; other values are printed as JSON. Human-only: requires an interactive terminal, no
agent environment and a typed confirmation word.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			toks, err := doc.ParsePointer(args[0])
			if err != nil {
				return xerr.Usage("the first argument is not a JSON Pointer (example: /database/url)")
			}
			e, err := loadEnv()
			if err != nil {
				return err
			}
			p, err := e.resolve(&pf)
			if err != nil {
				return err
			}
			enc, err := pair.ReadEncrypted(p.EncryptedPath)
			if err != nil {
				return err
			}
			ptr := doc.FormatPointer(toks)
			v, err := doc.Lookup(enc.Body, toks)
			if err != nil {
				return xerr.Failure("%s: not found in %s", displayPtr(ptr), p.Rel(p.EncryptedPath))
			}
			n := len(doc.Leaves(v))
			if err := e.protect(cmd, "reveal "+itoa(n)+" "+plural(n, "value", "values"), []string{p.Rel(p.EncryptedPath)}, bypass); err != nil {
				return err
			}
			sk, err := e.requireKey(enc)
			if err != nil {
				return err
			}
			dec, err := pair.DecryptAt(pair.StoreKeys(&sk, e.store), ptr, v)
			if err != nil {
				return err
			}
			if dec.Kind == doc.String && !asJSON {
				outf(cmd, "%s\n", dec.S)
				return nil
			}
			_, err = cmd.OutOrStdout().Write(doc.Marshal(dec))
			return err
		},
	}
	addPairFlags(c, &pf)
	c.Flags().BoolVar(&asJSON, "json", false, "print strings as JSON strings")
	addBypassFlag(c, &bypass, "skip the human-only gate (only when a human explicitly asked; audited)")
	return c
}

func displayPtr(p string) string {
	if p == "" {
		return "(root)"
	}
	return p
}

func itoa(n int) string { return strconv.Itoa(n) }

func atoiSafe(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}
