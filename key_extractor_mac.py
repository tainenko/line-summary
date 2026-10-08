"""
Relays the LINE PC wxSQLite3 encryption key on macOS. Unlike the Windows
module (key_extractor_windows.py), this module NEVER scans process memory and
NEVER needs elevated privileges itself.

WHY: macOS blocks one process from reading another's memory (task_for_pid /
mach_vm_read) far more aggressively than Windows does. LINE.app ships with
Apple's Hardened Runtime enabled, which refuses that access outright unless
either System Integrity Protection is relaxed or LINE.app is ad-hoc re-signed
to drop Hardened Runtime -- and even then the caller needs root. Running this
long-lived, unprivileged MCP server itself as root just to get that access
would be a much larger privilege expansion than the Windows design ever needed
(there, a same-user, non-elevated read is normally sufficient), so this server
process does not attempt the scan.

Instead, the user runs tools/mac_extract_key.py manually with sudo, once LINE
is running and LINE.app is ad-hoc re-signed (see README.md "macOS" section).
That separate script prints the decrypted key to the terminal ONLY -- never to
a file. The user then exports it as LINE_DB_KEY in the SAME shell before
starting Claude Code from it, so this server process inherits the environment
variable. This module just validates and relays it; it is not persisted to
disk, logged, or echoed anywhere by this module.

SECURITY (enforced):
- No memory access, no subprocess, no elevated privileges from this module.
- Key never written to disk, log, or server stdout by this module.
- Error messages never contain the key value.
"""
import os
import re

_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

_ENV_VAR = "LINE_DB_KEY"


def validate_key_format(candidate: str) -> bool:
    if len(candidate) not in (32, 64):
        return False
    return bool(_HEX_RE.fullmatch(candidate))


def extract_key(edb_path: str, require_consent: bool = True) -> str | None:
    """
    Validate and return the key already extracted out-of-process (see module
    docstring). `require_consent` is accepted for call-site parity with the
    Windows module but unused: this module never touches process memory, so
    there is nothing additional here to consent to.
    """
    from db_reader import preflight_db_access, DbAccessError, probe_key

    try:
        preflight_db_access(edb_path)
    except DbAccessError as e:
        raise RuntimeError(f"Cannot access the LINE database: {e}") from e

    raw = os.environ.get(_ENV_VAR)
    if not raw:
        raise RuntimeError(
            f"{_ENV_VAR} is not set. On macOS this server never reads LINE's "
            "process memory itself -- run "
            "'sudo <your venv python> tools/mac_extract_key.py --db-path <path>' "
            f"in a terminal, then `export {_ENV_VAR}=<printed key>` in that SAME "
            "shell before starting Claude Code from it. See README.md macOS section."
        )
    key = raw.strip().lower()
    if not validate_key_format(key):
        raise RuntimeError(f"{_ENV_VAR} is not a valid 32/64-character hex key")
    if not probe_key(edb_path, key):
        raise RuntimeError(
            f"{_ENV_VAR} did not decrypt the database. Re-run "
            "tools/mac_extract_key.py -- LINE may have rotated its key, or the "
            "wrong value was exported."
        )
    return key
