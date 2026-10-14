# jureuma

**jureuma** is an agent-safe configuration CLI. Humans write configuration and secrets in a plain JSON file that never leaves their machine. jureuma encrypts every value into a sibling file that is safe to commit and validates the configuration against a JSON Schema. AI agents can **set** values and **inject** them into processes, but they cannot **read** them through jureuma.

```text
config.unencrypted.json   plaintext, human-owned, always gitignored
config.encrypted.json     every value encrypted; field names readable; committed
config.schema.json        JSON Schema (inferred, then refined by agents); committed
```

- Values are encrypted one by one with X25519 public-key encryption. Anyone with the committed public key can encrypt (`set`), and only the private key in `~/.guiho/jureuma/keys/` (or a `JUREUMA_PRIVATE_KEY` variable in CI) can decrypt.
- `jureuma run -- <command>` decrypts in memory and passes the whole document to the child as JSON in `JUREUMA_CONFIG`. `--format flatten` (one variable per value) and `--format file` (a path to the document) are the alternatives. The child's output is redacted.
- Only one side of a pair exists at a time: `encrypt` deletes the unencrypted file and `decrypt` deletes the encrypted file (keeping a ciphertext copy under `~/.guiho/jureuma/state/` so the next `encrypt` reuses the key). Pass `--keep-both` to keep both.
- `decrypt`, `get`, `key show --private` and `key export` are human-only: they need an interactive terminal, no agent markers in the environment, and a typed confirmation word.
- `juju` is an optional short alias.

Built under the GUIHO CLI Convention: Go and Cobra, with versioned payloads behind a stable launcher in `~/.guiho/bin`.

## Install

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/CGuiho/jureuma/main/devops/install.ps1 | iex
```

macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/CGuiho/jureuma/main/devops/install.sh | sh
```

With an AI agent, give it this prompt:

```text
Load the jureuma install prompt from https://raw.githubusercontent.com/CGuiho/jureuma/main/internal/agentres/assets/prompts/guiho-p-jureuma-install.md (prompt guiho-p-jureuma-install) and follow it to install jureuma.
```

Verify the installation:

```sh
jureuma --version
```

The installers choose the latest stable release by default. `--version <semver>` or `--channel <name>` (`-Version` and `-Channel` in PowerShell) select another release, and `--dry-run` (`-DryRun`) shows the plan without changing anything. Each release artifact is checked against the release's `checksums.txt` (SHA-256) before anything is installed. Payloads go into `~/.guiho/jureuma/versions/<version>/`, the launcher into `~/.guiho/bin/`, and `~/.guiho/bin` is added to your user `PATH`. If any step fails, the previous installation is restored.

## Uninstall

> **Uninstalling removes all jureuma-owned data by default.** That covers the launcher and every installed version, `~/.guiho/jureuma/` (global configuration, state, audit log, caches), the `guiho-s-jureuma` skill copies, the jureuma block in `AGENTS.md`, the deny rules jureuma added, the `juju` alias and the project's `jureuma.yaml`. Private keys in `~/.guiho/jureuma/keys/` are deleted only after a human confirms in an interactive terminal; a non-interactive uninstall keeps them. Back them up first with `jureuma key export`.

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/CGuiho/jureuma/main/devops/uninstall.ps1 | iex
```

macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/CGuiho/jureuma/main/devops/uninstall.sh | sh
```

With an AI agent, give it this prompt:

```text
Load the jureuma uninstall prompt from https://raw.githubusercontent.com/CGuiho/jureuma/main/internal/agentres/assets/prompts/guiho-p-jureuma-uninstall.md (prompt guiho-p-jureuma-uninstall) and follow it to uninstall jureuma.
```

Run from the project root so the project items are found. Show the plan first (dry run, nothing is changed):

```sh
curl -fsSL https://raw.githubusercontent.com/CGuiho/jureuma/main/devops/uninstall.sh | sh -s -- --dry-run
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/CGuiho/jureuma/main/devops/uninstall.ps1))) -DryRun
```

Keep configuration and persistent data:

```sh
curl -fsSL https://raw.githubusercontent.com/CGuiho/jureuma/main/devops/uninstall.sh | sh -s -- --preserve-config --preserve-data
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/CGuiho/jureuma/main/devops/uninstall.ps1))) -PreserveConfig -PreserveData
```

| Option | PowerShell | Effect |
| --- | --- | --- |
| `--preserve-config` | `-PreserveConfig` | keep `jureuma.global.yaml` and the project's `jureuma.yaml` |
| `--preserve-data` | `-PreserveData` | keep `keys/`, `state/` and `audit.log` |
| `--dry-run` | `-DryRun` | print the REMOVE / PRESERVE plan only |
| `--yes` | `-Yes` | confirm without a prompt (keys still need a human) |

`jureuma uninstall` takes the same options. When the jureuma payload cannot run, the scripts fall back to a native plan that cannot edit `.claude/settings.json` safely: it lists the jureuma deny rules under PRESERVE so you can remove them by hand. The uninstaller never touches the jureuma block in `.gitignore` (plaintext files can outlive jureuma), your `*.encrypted.json`, `*.unencrypted.json` and `*.schema.json` files, the shared `~/.guiho`, `~/.guiho/bin` and `~/.guiho/.temp` directories, or `PATH`.

## Quick start

```sh
cd my-project
jureuma init                       # keys, jureuma.yaml, config pair, .gitignore block, starter schema, agent skill, AGENTS.md block
$EDITOR config.unencrypted.json    # a human writes plain JSON values
jureuma schema infer               # schema from the structure and types (never values); refine it, mark secrets "x-jureuma-secret": true
jureuma encrypt                    # write config.encrypted.json and delete the plaintext (--keep-both keeps it)
jureuma list                       # pointers, flattened names, types; never values
jureuma status                     # sync state per path
printf '%s' "$NEW_TOKEN" | jureuma set /apiKey --value-stdin
jureuma set /database/pool --json 20
jureuma run -- node server.js      # the app reads JSON.parse(process.env.JUREUMA_CONFIG)
jureuma run --format flatten -- ./start.sh   # DATABASE_URL, DATABASE_POOL, APIKEY, ...
jureuma check                      # schema, gitignore, tracked plaintext, keys, env collisions, deny rules
```

On a machine without the private key (a fresh agent sandbox or CI), `set`, `unset`, `list` and `status` still work. CI supplies the key through the variable that `jureuma key show` names.

## Agent-safety model

- **Agents can** run `set`, `unset`, `encrypt`, `run`, `list`, `status`, `check` and `schema infer`. None of these commands show plaintext or key material on stdout, stderr, in errors or in logs.
- **Only humans** can run `decrypt`, `get`, `key show --private`, `key export` and the deletion of `keys/` during uninstall. These commands check for a terminal, check for agent markers (`CLAUDECODE`, `CODEX_SANDBOX`, `CURSOR_AGENT`, `GEMINI_CLI`, …), and ask for a random typed word. A refusal exits `3`.
- `--dangerously-bypass-protections` exists for humans who explicitly ask for it. Every use is audited in `~/.guiho/jureuma/audit.log` (no values are written there). Setting `protections.allowBypass: false` in the global configuration turns the flag off. The flag is also refused when the protections block was edited by hand.
- `run` always strips `JUREUMA_PRIVATE_KEY*` from the child environment. It redacts decrypted values and their base64, URL and JSON encodings from the child's output. Flatten mode refuses code-loading names such as `LD_*`, `NODE_OPTIONS` and `PYTHONPATH`.
- `jureuma init` can add deny rules for `*.unencrypted.*` to agent tools such as Claude Code. The managed `AGENTS.md` block tells agents never to read plaintext files or anything under `~/.guiho/jureuma/`.
- Exit codes: `0` ok, `1` failure, `2` usage, `3` human-only, `4` validation, `5` key. `run` returns the child's code, or `125` with a `[JUREUMA:<KIND>]` prefix when jureuma itself failed.

This protects against accidental disclosure to agents. It does not protect against a hostile process that runs as the same user. See the design document for the honest limits.

## The `juju` alias

```sh
jureuma juju-enable    # installs ~/.guiho/bin/juju, which dispatches to the active jureuma
juju status
jureuma juju-disable   # removes only the alias jureuma installed
```

`juju-enable` refuses to overwrite a `juju` it does not own, such as Canonical's Juju, and warns when another `juju` comes earlier on `PATH`.

## Command reference

Every command documents itself:

```sh
jureuma --help-tree        # the whole command tree with every flag
jureuma <command> --help   # one command
jureuma --help-docs        # Markdown documentation for the root command (jureuma <command> --help-docs per command)
```

For the full behaviour, see [docs/2026-10-13-jureuma-design.md](docs/2026-10-13-jureuma-design.md). For the package layout, see [docs/2026-10-13-jureuma-implementation-contracts.md](docs/2026-10-13-jureuma-implementation-contracts.md).

## Development

Every project command is cataloged in [`runx.yaml`](runx.yaml). List them with `runx list`, and preview one with `runx run --dry-run <uid>` before running it. Versions, tags and the changelog are managed by Mirror ([`mirror.yaml`](mirror.yaml)). Directory documentation is one `*.xdocs.md` descriptor per directory (browse with `xdocs tree`).

```sh
runx run ci-check        # gofmt, vet (linux/darwin/windows), go test -race, smoke, shell lint, mirror, runx, xdocs
runx run test-e2e        # end-to-end tests against a built binary
runx run test-installers # install/uninstall scripts against a local release catalog
runx run release-prepare # dist/: six binaries, agent artifacts, schemas, artifacts.json, checksums.txt
```
