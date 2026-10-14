---
subject: jureuma-test-e2e
description: "End-to-end tests that build jureuma and drive it as a subprocess in throw-away homes and git projects (runx: test-e2e)."
parent: jureuma-test
children: []
files:
  "cli_test.go": "Command-surface tests (init, pairs, JSON output, schema infer, version, help, juju, key rotation)."
  "lifecycle_test.go": "Lifecycle tests with --keep-both (encrypt/decrypt round trips, gitignore invariant, status)."
  "onefile_test.go": "Default one-file lifecycle: encrypt deletes the plaintext, decrypt deletes the encrypted file, key and ciphertext restore from the saved copy or git HEAD, --keep-both."
  "main_test.go": "TestMain builds the binary with an injected version; per-test homes, projects and scrubbed environments."
  "protect_test.go": "Human-only gate, agent markers, bypass and protections-seal tests."
  "run_test.go": "run tests (json, flatten, file formats, --env, exit codes, private-key stripping, redaction)."
  "sentinel_test.go": "Sentinel values never displayed by any command or log."
  "values_test.go": "set/unset typing, paths, schema checks and status states."
  "review_test.go": "Regression tests for the security, correctness and convention review findings."
documents: {}
tags:
  - "test"
  - "e2e"
keywords:
  - "end-to-end"
  - "sentinel"
flags: []
status: stable
---

# jureuma-test-e2e

End-to-end tests that build jureuma and drive it as a subprocess in throw-away homes and git projects (runx: test-e2e).

## Files

- `cli_test.go`: Command-surface tests (init, pairs, JSON output, schema infer, version, help, juju, key rotation).
- `lifecycle_test.go`: Lifecycle tests with --keep-both (encrypt/decrypt round trips, gitignore invariant, status).
- `onefile_test.go`: Default one-file lifecycle: encrypt deletes the plaintext, decrypt deletes the encrypted file, key and ciphertext restore from the saved copy or git HEAD, --keep-both.
- `main_test.go`: TestMain builds the binary with an injected version; per-test homes, projects and scrubbed environments.
- `protect_test.go`: Human-only gate, agent markers, bypass and protections-seal tests.
- `run_test.go`: run tests (json, flatten, file formats, --env, exit codes, private-key stripping, redaction).
- `sentinel_test.go`: Sentinel values never displayed by any command or log.
- `values_test.go`: set/unset typing, paths, schema checks and status states.
- `review_test.go`: Regression tests for the security, correctness and convention review findings.
