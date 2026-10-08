# Changelog

## 2026-10-08 — macOS support

### Added

- `key_extractor_mac.py`: validates/relays a key already extracted
  out-of-process, via the `LINE_DB_KEY` environment variable. Never scans
  process memory or needs elevated privileges itself.
- `tools/mac_extract_key.py`: standalone, manually-run (`sudo`) CLI that scans
  LINE's process memory on macOS via `task_for_pid`/`mach_vm_read` (the mach
  equivalent of Windows' `ReadProcessMemory`) and prints the decrypted key to
  the terminal only. Not imported by the server; requires LINE.app to be
  ad-hoc re-signed first (drops Hardened Runtime) — see README.md's macOS
  section.
- `key_extractor_windows.py`: the original Windows memory-scanning module,
  renamed (no behavior change) so `key_extractor.py` could become a thin
  per-platform dispatcher.
- macOS default `.edb` discovery path
  (`~/Library/Containers/jp.naver.line.mac/.../Data/db`) in
  `line_mcp_server._default_data_dir()`.
- `macos-14` added to the offline-tests CI matrix.

### Why the macOS key flow differs from Windows

Windows allows a same-user, non-elevated process to read another process'
memory. macOS refuses that against a Hardened Runtime app (LINE.app ships with
it enabled) unless the target is ad-hoc re-signed and the caller runs as root.
Running the long-lived, unprivileged MCP server as root just for this was
judged a larger privilege expansion than acceptable, so the memory scan was
moved into a separate, manually-run, short-lived script
(`tools/mac_extract_key.py`), and the key crosses into the server process via
an environment variable the user exports in the same shell — never written to
disk, settings.json, or the macOS Keychain. This means macOS requires a fresh
manual extraction every time that shell/session starts, which Windows does
not. See README.md's "macOS 專屬設定" section for the exact steps.

### Verification

- Full offline test suite (129 tests, `-m "not integration"`) passes
  unmodified on macOS (Python 3.13, arm64); coverage 89.77%, above the 85%
  threshold.
- `tools/mac_extract_key.py`'s non-root guard, `find_line_pid()`, and its mach
  ctypes bindings were smoke-tested on a real Mac without LINE running (no
  LINE process found → correctly returns `None`; mach function pointers
  resolve). The actual `task_for_pid`/`mach_vm_read` scan against a live,
  ad-hoc re-signed LINE.app was **not** run — that requires `sudo` and a
  consequential, hard-to-reverse change to the user's installed LINE.app, so
  it was left for the user to run and verify themselves.

## 2026-10-08 — Core safety repair (breaking API)

Based on `bd3569e80af56cff342cab9690e6a6d0cb2f4f93`.

### Changed

- All MCP tools return page envelopes with explicit continuation/coverage metadata.
- History uses timestamp plus unique message ID keyset pagination, signed query-bound cursors, and millisecond `[since, until)` ranges accepting positive/negative timezone offsets.
- Unread samples explicitly report approximation and unknown synchronization; removed misleading `fully_synced`, `available_count`, and `missing_count` fields.
- Default-disabled server policy requires an explicit account database and chat allowlist. Discovery/contacts are separate opt-ins. Date-scoped configurations deny unread sampling. Per-call/process message and JSON-byte budgets are enforced.
- Chat/contact metadata pagination and malformed-ID checks fail closed; oversized items are reported without silently skipping them.
- The project skill now lives under `.claude/skills/line-summary/`, rejects instructions embedded in chat data, and defaults to replying without saving summary files.
- Runtime/test requirements are separate, exact-version/hash locked; MCP stays on 1.x and APSW on the 3.50 cipher line.
- Ordinary pytest, including `-m integration` alone, skips all real LINE tests before platform/process detection. Explicit `--run-live-line` is required for live access.
- Added synthetic-only CI for Linux/Windows and Python 3.11/3.12. No live LINE, credentials, production database, UI automation, or artifact upload is used by CI.

### Verification and limits

- Local Linux Python 3.12: 122 passed, 5 live tests skipped; runtime coverage 88.81% with branch measurement, retaining the 85% threshold.
- The patch was checked, applied to a clean baseline, and retested successfully. Independent security review reproduced and verified fixes for scope, cursor, minimum-byte-budget and null-ID regressions.
- CI results must be read from the exact PR head checks; a workflow definition alone is not a passing run.
- The upstream FastMCP/Pydantic lifespan warning remains documented. No real Windows LINE/schema/keys/network behavior was validated.
- History remains a live scan, not a snapshot or cloud-sync guarantee. Rowid reuse, edits and deletions can affect pagination while the database changes.
- Local read-only access does not prevent MCP host/model transmission or retention; memory-only key handling does not rule out OS swap or crash dumps.
- Message full-text search, a ChatGPT @ plugin, remote bridging, and de-identification/sensitive-data filtering are not implemented by this repair.

See [MIGRATION.md](MIGRATION.md) before upgrading clients or local settings.
