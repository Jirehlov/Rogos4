from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PatchRule:
    name: str
    rva: int
    expected: bytes
    replacement: bytes
    il_offset: int | None = None
    method_header: bytes | None = None


PatchReport = dict[str, str]
PatchResult = tuple[list[PatchReport], list[str]]


USER_METADATA_HEADER = bytes.fromhex("1B 30 09 00 58 04 00 00 2F 26 00 11")

LOGOS_RULES = (
    PatchRule(
        "freeze_display_name_refresh",
        0x35727C,
        bytes.fromhex("6F CF 44 00 06"),
        bytes.fromhex("DD 31 03 00 00"),
        0x107,
        USER_METADATA_HEADER,
    ),
    PatchRule(
        "about_display_name_source",
        0x2A2D48,
        bytes.fromhex("02 03 6F 4D 07 00 06 6F 62 06 00 0A 7D BB 4A 00 04"),
        bytes.fromhex("02 03 6F 45 06 00 06 6F EB 4F 00 06 7D BB 4A 00 04"),
        0x30,
    ),
    PatchRule(
        "about_display_name_assignment",
        0x4AEA34,
        bytes.fromhex("07 02 7B 8A CD 00 04 6F 4D 45 00 06 7D C1 4A 00 04"),
        bytes.fromhex("02 7B 87 CD 00 04 25 7B BB 4A 00 04 7D C1 4A 00 04"),
        0x284,
    ),
)

MANAGED_RULES = (
    PatchRule(
        "license_gate",
        0x2D83C,
        bytes.fromhex("36 02 28 8D 07 00 06 03 28 CC 08 00 06 2A"),
        bytes.fromhex("0A 17 2A"),
    ),
)

NATIVE_RULES = (
    PatchRule("feature_gate", 0x24E90, bytes.fromhex("40 53 48"), bytes.fromhex("B0 01 C3")),
    PatchRule("key_gate", 0x251D0, bytes.fromhex("40 53 48"), bytes.fromhex("B0 01 C3")),
    PatchRule(
        "identity_length",
        0x4F6B0,
        bytes.fromhex("0F 85 40 05 00 00"),
        bytes.fromhex("EB 11 90 90 90 90"),
    ),
    PatchRule(
        "identity_content",
        0x4F6BD,
        bytes.fromhex("0F 85 33 05 00 00"),
        bytes.fromhex("EB 04 90 90 90 90"),
    ),
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
        section = section_table + 40 * index
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", blob, section + 8)
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            file_offset = raw_pointer + rva - virtual_address
            if file_offset >= len(blob):
                raise ValueError(f"RVA 0x{rva:X} maps outside the file")
            return file_offset
    raise ValueError(f"RVA 0x{rva:X} is not in a PE section")


def method_il_file_offset(blob: bytes, method_rva: int, il_offset: int) -> int:
    body_offset = rva_to_file_offset(blob, method_rva)
    flags = struct.unpack_from("<H", blob, body_offset)[0]
    header_size = ((flags >> 12) & 0xF) * 4 if flags & 3 == 3 else 1
    offset = body_offset + header_size + il_offset
    if offset >= len(blob):
        raise ValueError(f"IL offset 0x{il_offset:X} maps outside the file")
    return offset


def rule_file_offset(blob: bytes, rule: PatchRule) -> int:
    if rule.il_offset is None:
        return rva_to_file_offset(blob, rule.rva)
    return method_il_file_offset(blob, rule.rva, rule.il_offset)


def rule_location(rule: PatchRule) -> str:
    if rule.il_offset is None:
        return f"0x{rule.rva:X}"
    return f"0x{rule.rva:X}+0x{rule.il_offset:X}"


def apply_rule(blob: bytearray, rule: PatchRule) -> PatchResult:
    if rule.method_header is not None:
        body_offset = rva_to_file_offset(blob, rule.rva)
        header = bytes(blob[body_offset : body_offset + len(rule.method_header)])
        if header != rule.method_header:
            raise ValueError(f"unsupported Logos build at RVA {rule_location(rule)}")

    offset = rule_file_offset(blob, rule)
    current = bytes(blob[offset : offset + len(rule.expected)])
    if current == rule.expected:
        blob[offset : offset + len(rule.replacement)] = rule.replacement
        return (
            [
                {
                    "name": rule.name,
                    "rva": rule_location(rule),
                    "file_offset": f"0x{offset:X}",
                    "before": current.hex(" "),
                    "after": rule.replacement.hex(" "),
                }
            ],
            [],
        )
    if current[: len(rule.replacement)] == rule.replacement:
        return [], [rule.name]
    raise ValueError(f"unsupported Logos build at RVA {rule_location(rule)}")


def apply_rules(blob: bytearray, rules: tuple[PatchRule, ...]) -> PatchResult:
    changes: list[PatchReport] = []
    already: list[str] = []
    for rule in rules:
        current_changes, current_already = apply_rule(blob, rule)
        changes.extend(current_changes)
        already.extend(current_already)
    return changes, already


def rule_matches(blob: bytes, rule: PatchRule) -> bool:
    try:
        if rule.method_header is not None:
            body_offset = rva_to_file_offset(blob, rule.rva)
            header = bytes(blob[body_offset : body_offset + len(rule.method_header)])
            if header != rule.method_header:
                return False
        offset = rule_file_offset(blob, rule)
        current = blob[offset : offset + len(rule.expected)]
        return current == rule.expected or current[: len(rule.replacement)] == rule.replacement
    except (ValueError, struct.error):
        return False


def detect_kind(target: Path, blob: bytes) -> tuple[str, tuple[PatchRule, ...]]:
    name = target.name.lower()
    if name == "logos.dll" or all(rule_matches(blob, rule) for rule in LOGOS_RULES):
        return "logos", LOGOS_RULES
    if name.startswith("libronix.digitallibrary.native.dll"):
        return "native", NATIVE_RULES
    if name.startswith("libronix.digitallibrary.dll"):
        return "managed", MANAGED_RULES
    if all(rule_matches(blob, rule) for rule in MANAGED_RULES):
        return "managed", MANAGED_RULES
    if all(rule_matches(blob, rule) for rule in NATIVE_RULES):
        return "native", NATIVE_RULES
    raise ValueError("unsupported target; expected a supported Logos binary")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=f".{target.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
        os.replace(temporary, target)
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Patch a Logos binary.")
    parser.add_argument("target", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    target = args.target.expanduser().resolve()
    if not target.is_file():
        print(f"target is not a file: {target}", file=sys.stderr)
        return 2

    try:
        original = target.read_bytes()
        kind, rules = detect_kind(target, original)
        patched = bytearray(original)
        changes, already = apply_rules(patched, rules)
        if not changes:
            report = {
                "status": "already_patched",
                "target": str(target),
                "kind": kind,
                "already": already,
                "sha256": sha256(original),
            }
        elif args.dry_run:
            report = {
                "status": "dry_run",
                "target": str(target),
                "kind": kind,
                "changes": changes,
                "already": already,
                "sha256": sha256(original),
            }
        else:
            backup = backup_path(target)
            shutil.copy2(target, backup)
            write_atomic(target, bytes(patched))
            report = {
                "status": "patched",
                "target": str(target),
                "kind": kind,
                "backup": str(backup),
                "changes": changes,
                "already": already,
                "input_sha256": sha256(original),
                "output_sha256": sha256(bytes(patched)),
            }
    except (OSError, ValueError, struct.error) as error:
        print(f"patch failed: {error}", file=sys.stderr)
        return 2

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
