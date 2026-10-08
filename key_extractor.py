"""
Platform dispatcher for LINE key extraction.

- Windows: key_extractor_windows.py scans LINE's process memory in-process
  (same user, no elevation needed).
- macOS: key_extractor_mac.py never scans memory itself; it relays a key the
  user already extracted out-of-process with tools/mac_extract_key.py (run
  once, manually, with sudo). See that module's docstring and the README's
  macOS section for why the two platforms differ here.

Import the concrete module directly (key_extractor_windows / key_extractor_mac)
if you need platform-specific functions this dispatcher does not re-export,
e.g. tools/scroll_backfill.py (Windows-only) imports find_line_pid from
key_extractor_windows directly.
"""
import sys

if sys.platform == "win32":
    from key_extractor_windows import extract_key, find_line_pid, validate_key_format
elif sys.platform == "darwin":
    from key_extractor_mac import extract_key, validate_key_format

    def find_line_pid():
        raise RuntimeError(
            "find_line_pid is Windows-only; macOS extraction runs separately "
            "via tools/mac_extract_key.py (see its --help)."
        )
else:
    def extract_key(*_args, **_kwargs):
        raise RuntimeError(f"Unsupported platform: {sys.platform}")

    def find_line_pid():
        raise RuntimeError(f"Unsupported platform: {sys.platform}")

    def validate_key_format(candidate: str) -> bool:
        import re
        return len(candidate) in (32, 64) and bool(re.fullmatch(r'[0-9a-fA-F]+', candidate))
