---
subject: jureuma-cli
description: "The Cobra command tree: every command, help flags (--help-docs, --help-tree), exit codes, the human-only gate and bypass handling, init, agent, juju alias, upgrade, uninstall and the bare-invocation update check."
parent: jureuma-internal
children: []
files:
  "cli.go": "Root command, Execute, global flags and exit-code mapping."
  "helpdocs.go": "--help-docs and --help-tree rendering."
  "context.go": "Shared command environment (project root, configuration, pair resolution)."
  "stash.go": "Saved copy of an encrypted file removed by decrypt, and its restore (saved copy, then git HEAD) for encrypt."
  "cmd_values.go": "encrypt, decrypt, set, unset and get."
  "cmd_run.go": "run: inject configuration into a child process with redacted output."
  "cmd_info.go": "list, status and check."
  "cmd_key.go": "key show, export, rotate and retire."
  "cmd_schema.go": "schema infer."
  "cmd_juju.go": "juju-enable and juju-disable (alias ownership by SHA-256)."
  "cmd_agent.go": "agent skill, instruction and prompt commands."
  "cmd_upgrade.go": "upgrade, upgrade check and upgrade list with the reinstall recovery block."
  "cmd_uninstall.go": "uninstall with the REMOVE/PRESERVE plan and key protection."
  "cmd_init.go": "init: configuration files, keys, pairs, gitignore block, schema, agent resources and deny rules."
  "denyrules.go": "Agent-tool deny rules for *.unencrypted.* in .claude/settings.json."
  "detach_unix.go": "Detached background update worker on Unix (Setsid)."
  "detach_windows.go": "Detached background update worker on Windows (DETACHED_PROCESS)."
  "cli_test.go": "In-process CLI tests, including the marker-value leak test."
  "upgrade_tx.go": "Synchronous upgrade transaction (staging, verification, versions/<v>, skills, current.json, launcher check, rollback) and the hidden __self-test command."
  "selfdelete_unix.go": "No-op running-image release for uninstall on Unix."
  "selfdelete_windows.go": "Moves the running executable aside so uninstall can remove it on Windows."
documents: {}
tags:
  - "go"
  - "cobra"
  - "commands"
keywords:
  - "init"
  - "run"
  - "set"
  - "get"
  - "decrypt"
  - "uninstall"
  - "upgrade"
  - "juju-enable"
flags: []
status: stable
---

# jureuma-cli

The Cobra command tree: every command, help flags (--help-docs, --help-tree), exit codes, the human-only gate and bypass handling, init, agent, juju alias, upgrade, uninstall and the bare-invocation update check.

## Files

- `cli.go`: Root command, Execute, global flags and exit-code mapping.
- `helpdocs.go`: --help-docs and --help-tree rendering.
- `context.go`: Shared command environment (project root, configuration, pair resolution).
- `stash.go`: Saved copy of an encrypted file removed by decrypt, and its restore (saved copy, then git HEAD) for encrypt.
- `cmd_values.go`: encrypt, decrypt, set, unset and get.
- `cmd_run.go`: run: inject configuration into a child process with redacted output.
- `cmd_info.go`: list, status and check.
- `cmd_key.go`: key show, export, rotate and retire.
- `cmd_schema.go`: schema infer.
- `cmd_juju.go`: juju-enable and juju-disable (alias ownership by SHA-256).
- `cmd_agent.go`: agent skill, instruction and prompt commands.
- `cmd_upgrade.go`: upgrade, upgrade check and upgrade list with the reinstall recovery block.
- `cmd_uninstall.go`: uninstall with the REMOVE/PRESERVE plan and key protection.
- `cmd_init.go`: init: configuration files, keys, pairs, gitignore block, schema, agent resources and deny rules.
- `denyrules.go`: Agent-tool deny rules for *.unencrypted.* in .claude/settings.json.
- `detach_unix.go`: Detached background update worker on Unix (Setsid).
- `detach_windows.go`: Detached background update worker on Windows (DETACHED_PROCESS).
- `cli_test.go`: In-process CLI tests, including the marker-value leak test.
- `upgrade_tx.go`: Synchronous upgrade transaction (staging, verification, versions/<v>, skills, current.json, launcher check, rollback) and the hidden __self-test command.
- `selfdelete_unix.go`: No-op running-image release for uninstall on Unix.
- `selfdelete_windows.go`: Moves the running executable aside so uninstall can remove it on Windows.
