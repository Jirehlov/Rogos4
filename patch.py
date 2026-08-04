from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
from pathlib import Path


MANAGED_RVA = 0x2D83C
MANAGED_EXPECTED = bytes.fromhex("36 02 28 8D 07 00 06 03 28 CC 08 00 06 2A")
MANAGED_PATCHED = bytes.fromhex("0A 17 2A")
NATIVE_RULES = (
    ("feature_gate", 0x24E90, bytes.fromhex("40 53 48"), bytes.fromhex("B0 01 C3")),
    ("key_gate", 0x251D0, bytes.fromhex("40 53 48"), bytes.fromhex("B0 01 C3")),
    ("identity_length", 0x4F6B0, bytes.fromhex("0F 85 40 05 00 00"), bytes.fromhex("EB 11 90 90 90 90")),
    ("identity_content", 0x4F6BD, bytes.fromhex("0F 85 33 05 00 00"), bytes.fromhex("EB 04 90 90 90 90")),
)


def rva_to_file_offset(blob: bytes, rva: int) -> int:
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise ValueError("target is not a PE image")
    pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("target has no PE signature")
    coff = pe_offset + 4
    _, section_count, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", blob, coff)
    section_table = coff + 20 + optional_size
    for index in range(section_count):
        offset = section_table + 40 * index
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", blob, offset + 8)
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            file_offset = raw_pointer + rva - virtual_address
            if file_offset < 0 or file_offset >= len(blob):
                raise ValueError(f"RVA 0x{rva:X} maps outside the file")
            return file_offset
    raise ValueError(f"RVA 0x{rva:X} is not in a PE section")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def apply_managed(blob: bytearray) -> tuple[list[dict[str, str]], list[str]]:
    offset = rva_to_file_offset(blob, MANAGED_RVA)
    current = bytes(blob[offset : offset + len(MANAGED_EXPECTED)])
    if current == MANAGED_EXPECTED:
        before = current.hex(" ")
        blob[offset : offset + len(MANAGED_PATCHED)] = MANAGED_PATCHED
        return ([{"name": "license_gate", "rva": f"0x{MANAGED_RVA:X}", "file_offset": f"0x{offset:X}", "before": before, "after": MANAGED_PATCHED.hex(" ")}], [])
    if current[: len(MANAGED_PATCHED)] == MANAGED_PATCHED:
        return ([], ["license_gate"])
    raise ValueError(f"unsupported managed Logos build at RVA 0x{MANAGED_RVA:X}")


def apply_native(blob: bytearray) -> tuple[list[dict[str, str]], list[str]]:
    changes = []
    already = []
    for name, rva, expected, replacement in NATIVE_RULES:
        offset = rva_to_file_offset(blob, rva)
        current = bytes(blob[offset : offset + len(expected)])
        if current == expected:
            before = current.hex(" ")
            blob[offset : offset + len(replacement)] = replacement
            changes.append({"name": name, "rva": f"0x{rva:X}", "file_offset": f"0x{offset:X}", "before": before, "after": replacement.hex(" ")})
        elif current[: len(replacement)] == replacement:
            already.append(name)
        else:
            raise ValueError(f"unsupported native Logos build at RVA 0x{rva:X}")
    return changes, already


def detect_kind(target: Path, blob: bytes) -> str:
    name = target.name.lower()
    if name.startswith("libronix.digitallibrary.native.dll"):
        return "native"
    if name.startswith("libronix.digitallibrary.dll"):
        return "managed"
    managed = False
    native = False
    try:
        offset = rva_to_file_offset(blob, MANAGED_RVA)
        current = blob[offset : offset + len(MANAGED_EXPECTED)]
        managed = current == MANAGED_EXPECTED or current[: len(MANAGED_PATCHED)] == MANAGED_PATCHED
    except ValueError:
        pass
    try:
        for _, rva, expected, replacement in NATIVE_RULES:
            offset = rva_to_file_offset(blob, rva)
            current = blob[offset : offset + len(expected)]
            if current == expected or current[: len(replacement)] == replacement:
                native = True
                break
    except ValueError:
        pass
    if managed and not native:
        return "managed"
    if native and not managed:
        return "native"
    raise ValueError("unsupported target; expected Libronix.DigitalLibrary.dll or Libronix.DigitalLibrary.Native.dll")


def backup_path(target: Path) -> Path:
    base = Path(f"{target}.bak-codex-auto")
    if not base.exists():
        return base
    index = 1
    while True:
        candidate = Path(f"{target}.bak-codex-auto-{index}")
        if not candidate.exists():
            return candidate
        index += 1


def write_atomic(target: Path, data: bytes) -> None:
    with tempfile.NamedTemporaryFile(dir=target.parent, prefix=f".{target.name}.", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
    try:
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Automatically patch the Logos local license gates.")
    parser.add_argument("target", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    target = args.target.expanduser().resolve()
    if not target.is_file():
        print(f"target is not a file: {target}", file=sys.stderr)
        return 2
    try:
        original = target.read_bytes()
        kind = detect_kind(target, original)
        patched = bytearray(original)
        if kind == "managed":
            changes, already = apply_managed(patched)
        else:
            changes, already = apply_native(patched)
        if not changes:
            report = {"status": "already_patched", "target": str(target), "kind": kind, "already": already, "sha256": sha256(original)}
        elif args.dry_run:
            report = {"status": "dry_run", "target": str(target), "kind": kind, "changes": changes, "already": already, "sha256": sha256(original)}
        else:
            backup = backup_path(target)
            shutil.copy2(target, backup)
            write_atomic(target, bytes(patched))
            report = {"status": "patched", "target": str(target), "kind": kind, "backup": str(backup), "changes": changes, "already": already, "input_sha256": sha256(original), "output_sha256": sha256(bytes(patched))}
    except (OSError, ValueError, struct.error) as error:
        print(f"patch failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())