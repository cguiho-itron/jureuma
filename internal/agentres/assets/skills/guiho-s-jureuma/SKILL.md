---
name: guiho-s-jureuma
description: Use whenever a project uses jureuma (or its juju alias) or needs configuration or secrets handled safely by an agent - installing, initializing, upgrading, or uninstalling jureuma; reading the shape of configuration with list/status/check; setting or unsetting values without seeing them; running commands with injected configuration (JUREUMA_CONFIG); writing or refining config.schema.json(c) JSON Schemas; rotating keys; or reporting jureuma bugs and improvements.
---

# guiho-s-jureuma

`jureuma` is an **agent-safe configuration CLI** (repository: https://github.com/CGuiho/jureuma). A human writes configuration and secrets in plain JSON; jureuma encrypts every value into a sibling file that is safe to commit and validates the configuration against a JSON Schema. Agents can **set** values and **inject** them into processes, but cannot **read** them through jureuma: decrypting and reading are human-only.

`juju` is an optional alias (`jureuma juju-enable`). It behaves exactly like `jureuma`. Always write `jureuma` in commands, scripts, and documentation.

## The file model

Every configuration is a **pair** sharing one stem, plus a schema:

```text
config.unencrypted.json   plaintext, human-owned, always gitignored   (or .unencrypted.jsonc)
config.encrypted.json     every value encrypted, keys readable, committed
config.schema.json        JSON Schema draft 2020-12, committed           (or .schema.jsonc)
```

- Default stem: `config` in the project root. `--name <stem>` selects another pair (`--name production`, `--name apps/api/config`). Pairs may be declared in `jureuma.yaml` under `pairs:`.
- `--encrypted-file`, `--unencrypted-file`, `--schema-file` override individual paths. Explicit names must still contain `.encrypted.` / `.unencrypted.`.
- The encrypted file mirrors the structure of the plaintext: object keys and array positions stay readable; each leaf is a `jureuma:1:<keyId>:...` ciphertext. The `$jureuma` key holds metadata (public key, key ID, schema path, sync state). Never edit `$jureuma` by hand.
- The filename tells you the state: `.unencrypted.` is plaintext, `.encrypted.` is ciphertext.
- Paths are always **JSON Pointers** (RFC 6901): `/database/url`, `/features/0`, `/a~1b` for key `a/b`, `/a~0b` for key `a~b`.
- Private keys live outside the project: `~/.guiho/jureuma/keys/<keyId>.json`, or the environment variables `JUREUMA_PRIVATE_KEY_<KEYID>` / `JUREUMA_PRIVATE_KEY` in CI. Agents usually do not have them and do not need them for `set`.

## Agent-safe rules (always apply)

1. **Never read plaintext.** Never read, open, `cat`, `grep`, `diff`, `head`, copy, upload, or attach any `*.unencrypted.*` file (`.json` or `.jsonc`), any temporary document jureuma creates, or anything under `~/.guiho/jureuma/` (keys, `audit.log`, `state/`, `run/`). The single exception is `~/.guiho/jureuma/jureuma.global.yaml`, which only holds policy settings.
2. **Never bypass protections on your own.** Never pass `--dangerously-bypass-protections` unless the human explicitly asked for it in **this** conversation. Never set or unset agent-marker environment variables to get past the human-only gate, and never drive a pseudo-terminal to answer its confirmation word.
3. **Human-only commands are for humans:** `jureuma decrypt`, `jureuma get`, `jureuma key show --private`, `jureuma key export`. They exit `3` when an agent runs them. When a human needs one, tell them the exact command to run themselves.
4. **Discover with metadata only:** `jureuma list`, `jureuma status`, `jureuma check`. Reading `*.encrypted.json` and `*.schema.json(c)` is fine; they contain no plaintext.
5. **Set values without echoing them:** pipe the value through stdin, `printf '%s' "$VALUE" | jureuma set /path --value-stdin`, so it stays out of shell history and logs. Use `--json` for anything that is not a string.
6. **Use values only through `jureuma run`.** Never try to extract a value from a `run` child: do not print it, write it to a file, encode or transform it, or send it anywhere. Output redaction exists to prevent accidents; deliberate extraction is forbidden.
7. **Never guess secrets.** When a value is missing, invalid, or unknown, ask the human to provide it (they can run `jureuma set` themselves or edit the plaintext file and run `jureuma encrypt`).
8. **Never commit plaintext.** Do not remove the jureuma block from `.gitignore`, do not `git add -f` an unencrypted file, and do not weaken `jureuma.yaml` to make a check pass.
9. **Never paste values into prompts, issues, commits, docs, or logs**, including ciphertexts and key material.

## Install

Install jureuma by following the install prompt referenced in the README (https://github.com/CGuiho/jureuma#install): load the `guiho-p-jureuma-install` prompt and follow it. In short, run exactly one command for the host:

```text
Windows (PowerShell):  irm https://raw.githubusercontent.com/CGuiho/jureuma/main/devops/install.ps1 | iex
macOS / Linux:         curl -fsSL https://raw.githubusercontent.com/CGuiho/jureuma/main/devops/install.sh | sh
```

Add `--version 'X.Y.Z'` or `--channel '<name>'` (PowerShell: `-Version` / `-Channel`) to pin a release. Never install jureuma through a package manager (npm, Bun, pip, Homebrew, or similar); no such package exists. Verify with `jureuma --version` (it prints a raw SemVer such as `0.3.1`).

## Initialize

Run `jureuma init` in the project root after every install, reinstall, or upgrade. It is safe to re-run. It:

- installs or refreshes the `guiho-s-jureuma` skill in the global agent-skill directories;
- creates `AGENTS.md` if needed and applies or refreshes jureuma's managed instruction block (content outside the block is never touched);
- ensures `~/.guiho/jureuma/jureuma.global.yaml` and the project `jureuma.yaml` exist and are valid, and asks for the `agent.evolution` policy;
- for each pair: creates a key pair and an empty encrypted and unencrypted file when no encrypted file exists (it never replaces the key of an existing encrypted file), adds the `.gitignore` block for `*.unencrypted.json` / `*.unencrypted.jsonc`, creates a starter schema when missing, and offers agent-tool deny rules for `*.unencrypted.*` (recommend accepting).

`private key not available (expected on agent and CI machines)` is informational, not a failure. `init` needs an interactive terminal when it must ask questions; when it fails for that reason, ask the human to run it.

## Everyday workflows

**Understand the configuration.**

```sh
jureuma list                  # pointers, flattened env names, types (schema-declared without the key)
jureuma status                # read-only sync state per path
jureuma check                 # schema, gitignore, tracked plaintext, key consistency, env collisions, deny rules
```

**Set a value** (encrypts with the committed public key; no private key needed):

```sh
printf '%s' "$DATABASE_URL" | jureuma set /database/url --value-stdin       # string
jureuma set /database/pool --json 20                                       # number
jureuma set /features/beta --json true                                     # boolean
printf '%s' '{"host":"db","port":5432}' | jureuma set /database --json --value-stdin   # object, expanded per leaf
jureuma set /features/- --json '"search"'                                  # append to an array
jureuma set /optional --json null                                          # stores null (not the same as unset)
```

Values default to strings; if the schema says the path is not a string, `set` fails with exit `4` and suggests `--json`. Missing parent objects are created. `set` writes the encrypted file first, then mirrors the value into an existing `.json` unencrypted file. It never prints the value. Use `--value-file <path>` only for a file you created yourself for this purpose, never for an `*.unencrypted.*` file.

**Remove a value:** `jureuma unset /path` removes a member or subtree (parents remain as `{}`). Without the private key only object members and the **last** array element can be removed; for other array elements, ask the human.

**Run with configuration:**

```sh
jureuma run -- npm start
jureuma run -- python -m app
jureuma run --name production -- ./server
```

By default the child receives the **whole decrypted document, JSON-stringified, in `JUREUMA_CONFIG`**:

```js
const config = JSON.parse(process.env.JUREUMA_CONFIG); // Node / Bun
```

```python
config = json.loads(os.environ["JUREUMA_CONFIG"])  # Python
```

```go
var cfg Config
err := json.Unmarshal([]byte(os.Getenv("JUREUMA_CONFIG")), &cfg) // Go
```

Other mappings:

| Flag | Effect |
| --- | --- |
| `--format json` (default) | Whole document as JSON in `--env-name` (default `JUREUMA_CONFIG`). |
| `--format flatten` | One variable per leaf: `/database/url` becomes `DATABASE_URL`; `--prefix APP_` prepends a prefix. Names that collide, and names that load or run code or belong to jureuma (`LD_*`, `DYLD_*`, `GIT_*`, `JAVA_*`, `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`, `PAGER`, `EDITOR`, `PATH`, `JUREUMA_*`, ...), are refused; map one explicitly with `--env` only when the human asked for it. `null` and empty containers are not set. |
| `--format file` | `--env-name` holds a path to the whole document (a memfd on Linux, a `0600` temp file elsewhere, deleted when the child exits). |
| `--env-name NAME` | Variable name for `json` and `file` formats (always set, replacing an inherited value; denylisted names are refused). |
| `--env NAME=/pointer` | Also inject one value (repeatable). |
| `--override` | Flattened and `--env` values win over variables already in the environment (default: existing variables win). |

`run` removes every `JUREUMA_PRIVATE_KEY*` variable from the child, redacts config values (and their common encodings) and private keys in the child's stdout and stderr as `[REDACTED]`, and returns the child's exit code. Exit `125` with a `[JUREUMA:...]` prefix means jureuma failed before or around the child. Seeing `[REDACTED]` is expected; do not try to recover what was redacted. Make the application read `JUREUMA_CONFIG` (or flattened variables) rather than adding `.env` files.

**Human edit cycle** (tell the human; do not do it yourself): `jureuma decrypt` (human-only; deletes `config.encrypted.json`) → edit `config.unencrypted.json` → `jureuma encrypt` (deletes `config.unencrypted.json`). Only one side of a pair exists at a time unless `--keep-both` is passed; while a pair is decrypted, `set`, `run` and `list` report the encrypted file as missing, so ask the human to finish with `jureuma encrypt`. An agent may run `jureuma encrypt` when the human asks, because jureuma reads the plaintext internally; it refuses paths in `conflict` unless `--force` is given, and an agent must not pass `--force` without the human's approval.

**Status states:** `in-sync`; `unencrypted-newer` (run `jureuma encrypt`); `encrypted-newer` (a human runs `jureuma decrypt`); `conflict` (a human resolves, then `encrypt --force` or `decrypt --force`); `unencrypted-missing` and `key-unavailable` (normal on agent and CI machines).

## Command reference

Pair-aware commands accept `--name`, `--encrypted-file`, `--unencrypted-file`, `--schema-file`. Every command accepts `-h/--help`, `--help-docs`, `--help-tree`, `--help-tree-depth`, `--help-tree-global-flags`. `jureuma -v` / `jureuma --version` prints the raw version. `[P]` = protected, human-only.

| Command | Purpose |
| --- | --- |
| `jureuma init` | Initialize or reconcile jureuma for the project (see above). |
| `jureuma encrypt [--force] [--keep-both]` | Unencrypted file → encrypted file; validates the whole document first; reuses unchanged ciphertexts; deletes the unencrypted file unless `--keep-both`. |
| `jureuma decrypt [--force] [--keep-both]` [P] | Encrypted file → unencrypted file; deletes the encrypted file unless `--keep-both`. |
| `jureuma set <pointer> [value] [--json] [--value-stdin] [--value-file <path>] [--allow-invalid]` | Encrypt and store one value. |
| `jureuma unset <pointer> [--allow-invalid]` | Remove one value or subtree. |
| `jureuma get <pointer>` [P] | Print one plaintext value. |
| `jureuma run [--format json\|flatten\|file] [--env-name NAME] [--prefix P] [--env NAME=/ptr]... [--override] -- <cmd> [args...]` | Run a command with injected, redacted configuration. |
| `jureuma list` | Pointers, flattened names, and types. Never values. |
| `jureuma status` | Read-only per-path sync state. |
| `jureuma check` | Full consistency and validation check (needs the key for value validation). |
| `jureuma key show` | Public key and key ID. `--private` is [P]. |
| `jureuma key export` [P] | Print the private key for backup. |
| `jureuma key rotate` | New key pair, re-encrypt every value, retire the old key. Needs the private key. Rotation does not revoke git history. |
| `jureuma key retire <keyId>` | Delete a retired key once no ciphertext uses it. |
| `jureuma schema infer [--force]` | Generate a starter schema from structure and JSON types (never values). |
| `jureuma juju-enable` / `juju-disable` | Install or remove the `juju` alias in `~/.guiho/bin`. |
| `jureuma agent skill install\|uninstall\|upgrade\|list\|show` | Manage the bundled skills (this one is `guiho-s-jureuma`). |
| `jureuma agent instruction apply\|remove\|upgrade\|show` | Manage jureuma's managed block in `AGENTS.md`. |
| `jureuma agent prompt list\|show` | Inspect bundled prompts: `guiho-p-jureuma` (default), `guiho-p-jureuma-install`, `guiho-p-jureuma-uninstall`. |
| `jureuma upgrade` / `upgrade check` / `upgrade list` | Upgrade the whole release in place (verified, rolled back on failure), check for one, list releases. Refuses while `jureuma run` sessions are alive (`--force` stops them gracefully, right before activation). Then run `jureuma init` and `jureuma --version`. |
| `jureuma uninstall [--preserve-config] [--preserve-data] [--dry-run] [--yes]` | Remove jureuma. Deleting `keys/` always needs the human-only gate; non-interactive runs preserve keys. Follow the `guiho-p-jureuma-uninstall` prompt. |

**Exit codes:** `0` success, `1` failure, `2` usage error, `3` protected operation refused (human-only), `4` validation failed (schema), `5` key not found, key mismatch, or decryption failed. `run` returns the child's code, or `125` for a jureuma-side failure. Error messages contain JSON Pointers, schema keywords, and schema parameters only, never values.

**Configuration (`jureuma.yaml`, project root):**

```yaml
# yaml-language-server: $schema=https://github.com/CGuiho/jureuma/releases/download/v<version>/jureuma.schema.json
pairs:
  - name: config
    schema: ./config.schema.json
run:
  format: json
  envName: JUREUMA_CONFIG
  prefix: ""
  override: false
agent:
  evolution:
    upgrade: always-ask
    issues: { bugs: always-ask, improvements: always-ask, reviews: always-ask }
```

`protections` (`allowBypass`, `agentEnvMarkers`) exists only in `~/.guiho/jureuma/jureuma.global.yaml` and is rejected in `jureuma.yaml`. Never edit it.

## Writing the schema

The schema is a standard **JSON Schema draft 2020-12** document in `<stem>.schema.json`, or `<stem>.schema.jsonc` when you want comments. It is committed and must never contain configuration values. Nobody writes it from scratch:

1. **Generate:** `jureuma schema infer` (add `--name <stem>` for another pair). jureuma reads the structure and JSON types internally, never the values, and writes objects with `required` for every present key and `additionalProperties: false`, homogeneous arrays as `items`, mixed arrays as `prefixItems`. Without a plaintext file it infers structure only from the encrypted file and leaves leaf types unconstrained (`{}`). It refuses to overwrite an existing schema; pass `--force` only when replacing the old schema is intended (refinements are lost).
2. **Refine** the generated file by editing it, using only what you know from field names, the code that consumes the configuration, and what the human told you. Never infer constraints by looking at values.
3. **Verify:** `jureuma check` (it also warns while the permissive starter schema from `init` is still in use).

What to add while refining:

- `description` on every property: what it configures and who sets it. `title` and `$comment` are also fine.
- Precise `type`s (`string`, `integer`, `number`, `boolean`, `object`, `array`, `null`, or a list such as `["string", "null"]`).
- Constraints: `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `multipleOf`, `minLength`, `maxLength`, `pattern`, `minItems`, `maxItems`, `uniqueItems`, `minProperties`, `maxProperties`, `required`, `additionalProperties`, `patternProperties`, `propertyNames`, `enum` (non-secret choices such as log levels).
- Composition: `anyOf`, `oneOf`, `allOf`, `if`/`then`/`else`, `$ref` with `$defs` for repeated shapes.
- `format`, only from this list (any other format is an error, so typos never pass silently): `date-time`, `date`, `time`, `email`, `hostname`, `ipv4`, `ipv6`, `uri`, `uuid`.
- `"x-jureuma-secret": true` on every secret (passwords, tokens, API keys, private keys, connection strings with credentials, signing secrets). `run` then redacts the value in any form and length. When unsure, mark it secret.
- Unknown keywords are errors; custom annotations must start with `x-`.

Never put real values anywhere in the schema: no real values in `default`, `examples`, `const`, or `enum`, and none of those keywords at all on `x-jureuma-secret` paths (`jureuma check` warns about them). Placeholders that are obviously not real (`"postgres://user:password@host:5432/db"` as a description example) belong in `description` text, if anywhere.

Example refinement:

```jsonc
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["database", "logLevel"],
  "additionalProperties": false,
  "properties": {
    "database": {
      "type": "object",
      "description": "Primary PostgreSQL database.",
      "required": ["url", "pool"],
      "additionalProperties": false,
      "properties": {
        "url": {
          "type": "string",
          "format": "uri",
          "description": "Connection URL including credentials. Set by a human.",
          "x-jureuma-secret": true
        },
        "pool": {
          "type": "integer",
          "minimum": 1,
          "maximum": 100,
          "description": "Maximum open connections."
        }
      }
    },
    "logLevel": {
      "enum": ["debug", "info", "warn", "error"],
      "description": "Minimum log level."
    }
  }
}
```

When the application adds a setting: add it to the schema first (with `description`, type, constraints, and `x-jureuma-secret` when relevant), then set it with `jureuma set`, or ask the human to set a secret. Several pairs may share one schema (for example `production` and `staging` both pointing at `config.schema.json` through `jureuma.yaml`).

## CLI Evolution and Feedback

While using this CLI, treat observed bugs, useful improvements, and actionable review findings as opportunities to evolve the CLI. Follow the effective agent-evolution policy. When issue creation is authorized, create an issue in the CLI's GitHub repository and provide the resulting issue URL to the user.

- Repository: https://github.com/CGuiho/jureuma
- New issue: https://github.com/CGuiho/jureuma/issues/new (or `gh issue create --repo CGuiho/jureuma`)

**Read the effective policy first.** Before upgrading jureuma or creating an issue, read `agent.evolution` from the project `jureuma.yaml`; any field it omits is inherited from `~/.guiho/jureuma/jureuma.global.yaml`; any field still missing is `always-ask`. Fields: `upgrade`, `issues.bugs`, `issues.improvements`, `issues.reviews`. Each takes exactly one value:

- `disabled`: do not perform the action and do not ask for permission to perform it. You may still tell the user what you observed.
- `always-ask`: explain the proposed action, ask the user for permission, and wait for approval before acting. Each action needs a new approval. For example: "I found something that appears to be a bug in jureuma. Do you allow me to create an issue in the jureuma GitHub repository?"
- `always-proceed`: perform the action without asking again, then report the result.

**Upgrades.** While using jureuma, check for a newer release with `jureuma upgrade check` (subject to `agent.evolution.upgrade`; skip the check when it is `disabled`). With `always-ask`, tell the user the target version and wait for approval; with `always-proceed`, upgrade. After any upgrade (or reinstall): verify `jureuma --version` prints the expected version, rerun `jureuma init`, and verify `jureuma --version` again. If the upgrade fails, run the reinstall command that `jureuma upgrade` printed. `jureuma upgrade` refuses while `jureuma run` sessions are active; do not pass `--force` unless the user agrees to stop them.

**Recognizing what to report** (jureuma-specific):

- **Bugs:** a plaintext value, ciphertext, or key material appears where it should not (output, error, log, audit line); `[REDACTED]` missing for a value that should be redacted; a command crashes or exits with a code that contradicts the documented exit codes; `status` reports a wrong state; `set` loses or corrupts a value; `check` passes on a tracked `*.unencrypted.*` file; the `AGENTS.md` block or `.gitignore` block damages content outside it; a valid JSONC file or valid draft 2020-12 schema is rejected (or an invalid one accepted).
- **Improvements:** a missing schema keyword or `format`, an unclear error message, a workflow that forces a human step that could be safely automated, a missing `--help-docs` example, friction in `run` integration for a language or framework.
- **Reviews:** documentation that contradicts behaviour, inconsistencies between this skill, the instruction, and `--help-docs`, or design concerns about agent safety.

**Secret-safe issue content.** An issue may contain only: JSON Pointer paths, JSON types, schema keywords and schema parameters, exit codes, jureuma versions (`jureuma --version`), OS and architecture, and command lines **with every value removed** (write `<value>`). An issue must never contain: `jureuma run` output, contents of any `*.unencrypted.*` file or of temporary files, ciphertexts or `$jureuma` blocks, private key material (anything starting with `jureuma-sk-1:`), environment dumps, or anything from `~/.guiho/jureuma/`. Report a suspected redaction failure by describing it with the leaked text replaced (for example `<leaked value, 24 chars>`), never by quoting it. When in doubt, leave it out and tell the user.

**After creating an issue,** give the user the direct URL of the created issue. Never claim an issue was created unless creation succeeded and returned a URL.
