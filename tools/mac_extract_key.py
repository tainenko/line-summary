"""
One-time, manual LINE PC (macOS) key extractor. NOT part of the MCP server;
NOT imported by it. Run by hand, in a terminal, with sudo.

WHY THIS IS SEPARATE FROM THE SERVER
macOS enforces much stronger process-isolation than Windows: reading another
app's memory (task_for_pid + mach_vm_read, the macOS equivalent of Windows'
ReadProcessMemory) is refused outright against a Hardened Runtime app like
LINE.app, unless the caller runs with root AND the target has been stripped of
Hardened Runtime (ad-hoc re-signed). The long-running MCP server should not run
as root just to get this one-off access, so that access lives here instead, in
a short-lived script you run yourself.

BEFORE RUNNING THIS, ONE TIME
Ad-hoc re-sign your installed LINE.app to drop Hardened Runtime. This REMOVES
LINE's official code signature; macOS Gatekeeper will no longer vouch for it,
and you must redo this after every LINE update. Make your own decision; this
script does not do it for you:

    cp -R /Applications/LINE.app ~/Desktop/LINE.app.backup   # optional backup
    sudo codesign --remove-signature /Applications/LINE.app
    sudo codesign --force --deep --sign - /Applications/LINE.app

USAGE (LINE must already be running and logged in)

    sudo <your venv's python3> tools/mac_extract_key.py --db-path /absolute/path/to/your.edb

The found key is printed to YOUR terminal ONLY -- this script never writes it
to a file, log, or any other process. Copy it, then in that SAME shell, before
starting Claude Code from it:

    export LINE_DB_KEY=<the printed key>

SECURITY (enforced)
- Local only; no network access.
- Interactive consent required unless --yes is passed.
- Key never written to disk or log by this script, and never passed as a CLI
  argument (which other local users could see via `ps`) -- only printed once
  to this terminal's stdout for you to copy into your own shell's env var.
- Error messages never contain key candidates or chat content.
"""
import argparse
import ctypes
import os
import re
import subprocess
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_LINE_EXECUTABLE = "/Applications/LINE.app/Contents/MacOS/LINE"

# Mirrors key_extractor_windows.py's rationale: cap region size so the scan
# finishes quickly, and scan both ASCII and UTF-16LE since LINE (Qt) holds
# strings in both forms depending on code path.
_MAX_REGION_BYTES = 128 * 1024 * 1024
_PAT32 = re.compile(rb'(?<![0-9a-zA-Z])([0-9a-fA-F]{32})(?![0-9a-zA-Z])')
_PAT32_U16 = re.compile(rb'(?:[0-9a-fA-F]\x00){32}')

_VM_PROT_READ = 0x01
_VM_REGION_BASIC_INFO_64 = 9

mach_port_t = ctypes.c_uint32
kern_return_t = ctypes.c_int
vm_map_t = mach_port_t
mach_vm_address_t = ctypes.c_uint64
mach_vm_size_t = ctypes.c_uint64
mach_msg_type_number_t = ctypes.c_uint32
vm_region_flavor_t = ctypes.c_int


class _VMRegionBasicInfo64(ctypes.Structure):
    _fields_ = [
        ("protection", ctypes.c_int32),
        ("max_protection", ctypes.c_int32),
        ("inheritance", ctypes.c_uint32),
        ("shared", ctypes.c_int32),
        ("reserved", ctypes.c_int32),
        ("offset", ctypes.c_uint64),
        ("behavior", ctypes.c_int32),
        ("user_wired_count", ctypes.c_uint16),
    ]


_INFO_COUNT = ctypes.sizeof(_VMRegionBasicInfo64) // 4


def _libc():
    lib = ctypes.CDLL(None, use_errno=True)
    lib.mach_task_self.restype = mach_port_t

    lib.task_for_pid.restype = kern_return_t
    lib.task_for_pid.argtypes = [mach_port_t, ctypes.c_int, ctypes.POINTER(mach_port_t)]

    lib.mach_vm_region.restype = kern_return_t
    lib.mach_vm_region.argtypes = [
        vm_map_t, ctypes.POINTER(mach_vm_address_t), ctypes.POINTER(mach_vm_size_t),
        vm_region_flavor_t, ctypes.c_void_p, ctypes.POINTER(mach_msg_type_number_t),
        ctypes.POINTER(mach_port_t),
    ]

    lib.mach_vm_read_overwrite.restype = kern_return_t
    lib.mach_vm_read_overwrite.argtypes = [
        vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t,
        ctypes.POINTER(mach_vm_size_t),
    ]

    lib.mach_port_deallocate.restype = kern_return_t
    lib.mach_port_deallocate.argtypes = [mach_port_t, mach_port_t]
    return lib


def validate_key_format(candidate: str) -> bool:
    if len(candidate) not in (32, 64):
        return False
    return bool(re.fullmatch(r'[0-9a-fA-F]+', candidate))


def find_line_pid() -> int | None:
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,command="], capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        pid_str, _, command = line.partition(" ")
        if command.strip() == _LINE_EXECUTABLE:
            try:
                return int(pid_str)
            except ValueError:
                continue
    return None


def _scan_memory_regions(pid: int) -> list[str]:
    """Scan LINE's private, readable memory for 32-hex key candidates, most
    frequent first. Requires root AND a target that is not Hardened-Runtime
    protected (see module docstring)."""
    lib = _libc()
    task = mach_port_t(0)
    kr = lib.task_for_pid(lib.mach_task_self(), pid, ctypes.byref(task))
    if kr != 0:
        raise RuntimeError(
            f"task_for_pid failed (kern_return_t={kr}). This needs LINE.app "
            "ad-hoc re-signed (drops Hardened Runtime) AND this script run "
            "with sudo -- see this file's module docstring."
        )

    counts: "Counter[str]" = Counter()
    address = mach_vm_address_t(0)
    try:
        while True:
            size = mach_vm_size_t(0)
            info = _VMRegionBasicInfo64()
            info_count = mach_msg_type_number_t(_INFO_COUNT)
            obj_name = mach_port_t(0)
            kr = lib.mach_vm_region(
                task, ctypes.byref(address), ctypes.byref(size),
                _VM_REGION_BASIC_INFO_64, ctypes.byref(info), ctypes.byref(info_count),
                ctypes.byref(obj_name),
            )
            if kr != 0:
                break  # no more regions

            readable = (
                (info.protection & _VM_PROT_READ)
                and not info.shared
                and 0 < size.value <= _MAX_REGION_BYTES
            )
            if readable:
                buf = ctypes.create_string_buffer(size.value)
                outsize = mach_vm_size_t(0)
                kr2 = lib.mach_vm_read_overwrite(
                    task, address.value, size.value,
                    ctypes.cast(buf, ctypes.c_void_p).value, ctypes.byref(outsize),
                )
                if kr2 == 0 and outsize.value > 0:
                    chunk = buf.raw[:outsize.value]
                    for m in _PAT32.findall(chunk):
                        counts[m.decode('ascii').lower()] += 1
                    for m in _PAT32_U16.findall(chunk):
                        try:
                            counts[m.decode('utf-16le').lower()] += 1
                        except Exception:
                            pass

            next_addr = address.value + size.value
            if size.value == 0 or next_addr <= address.value:
                break
            address = mach_vm_address_t(next_addr)
    finally:
        lib.mach_port_deallocate(lib.mach_task_self(), task)

    return [c for c, _ in counts.most_common() if validate_key_format(c)]


def _confirm_consent() -> bool:
    print("\n" + "=" * 58)
    print("LINE Summary -- Memory Access Required (macOS, one-time)")
    print("=" * 58)
    print("This tool reads LINE's process memory to extract the database")
    print("encryption key. The key is printed to THIS terminal only and is")
    print("never written to disk, a log, or any other process by this tool.")
    print("OS paging, hibernation, or crash dumps may still retain it.")
    print("=" * 58)
    return input("Proceed? Type 'yes' to continue: ").strip().lower() == "yes"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="One-time manual LINE key extractor for macOS. Run with sudo."
    )
    parser.add_argument("--db-path", required=True, help="Absolute path to your account's .edb")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive consent prompt")
    args = parser.parse_args()

    if sys.platform != "darwin":
        print("This script is macOS-only; see key_extractor_windows.py for Windows.", file=sys.stderr)
        sys.exit(1)

    if os.geteuid() != 0:
        print(
            "Run this with sudo, e.g.:\n"
            "  sudo <your venv's python3> tools/mac_extract_key.py --db-path <path>",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.yes and not _confirm_consent():
        sys.exit(1)

    from db_reader import preflight_db_access, DbAccessError, probe_key

    try:
        preflight_db_access(args.db_path)
    except DbAccessError as e:
        print(f"Cannot access the LINE database: {e}", file=sys.stderr)
        sys.exit(1)

    pid = find_line_pid()
    if pid is None:
        print(f"LINE is not running (looked for {_LINE_EXECUTABLE}).", file=sys.stderr)
        sys.exit(1)

    candidates = _scan_memory_regions(pid)
    if not candidates:
        print("No key-shaped candidates found in LINE's memory.", file=sys.stderr)
        sys.exit(1)

    for candidate in candidates:
        if probe_key(args.db_path, candidate):
            print("\nKey found. Shown ONCE below; nothing is written to disk.")
            print("In the SAME shell, before starting Claude Code from it, run:\n")
            print(f"    export LINE_DB_KEY={candidate}\n")
            return

    print(
        "Found candidates but none decrypted the database. The DB is readable "
        "(preflight passed), so LINE likely rotated its key.",
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
