use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

mod crypto;
mod key_store;
mod legacy;
mod util;

use crypto::{salsa_block, sha1_bytes, sha1_file_range, xor_salsa_range};
use key_store::KeyStore;
use util::{hex_upper, json_string};

const LRES_HEADER_SIZE: usize = 0x200;
const ENCRYPTED_START: usize = 0x200;
const MAGIC: &[u8; 8] = b"LRES01\r\n";
const LICENSE_MAGIC: &[u8; 4] = b"LIC4";
const LICENSE_SECTION_MAGIC: &[u8; 8] = b"LSES\0\0\x01\0";
const DEFAULT_ROUNDS: u32 = 8;
const LICENSE_ROUNDS: u32 = 20;

struct LicenseRecord {
    record_offset: usize,
    key_offset: usize,
    resource_id: String,
    key_hex: String,
    trailing_hex: String,
}

struct LresHeader {
    offset: usize,
    resource_id: String,
    duplicate_resource_id: String,
    resource_date: String,
    driver: String,
    driver_version: String,
    header_byte_ba: u8,
    flags: u8,
    stored_file_length: u32,
    data_start: u32,
    format_parameter: u32,
    header_parameter: [u8; 16],
    payload_sha1: [u8; 20],
}

struct LicenseContainer {
    file_size: usize,
    format_version: u32,
    declared_payload_length: u32,
    declared_payload_end: usize,
    section_offsets: Vec<usize>,
    nonce_hex: String,
    inner_size: usize,
    user_id: String,
    records: Vec<LicenseRecord>,
    unique_keys: Vec<String>,
    added_keys: Vec<String>,
    key_db_path: String,
    key_db_updated: bool,
    header_prefix_hex: String,
    file_sha1: String,
    warnings: Vec<String>,
}

struct ArchiveEntry {
    record_offset: usize,
    offset: u32,
    length: u32,
    name: String,
}

struct XmlField {
    kind: String,
    path: String,
    value: String,
}

struct DecodedResource {
    path: String,
    key_hex: String,
    outer: LresHeader,
    inner: LresHeader,
    plaintext: Vec<u8>,
    entries: Vec<ArchiveEntry>,
    metadata_entry: Option<usize>,
    fields: Vec<XmlField>,
    decompressions: Vec<DecompressionProbe>,
    legacy: Vec<legacy::LegacyInfo>,
    warnings: Vec<String>,
}

struct DecompressionProbe {
    entry_index: usize,
    name: String,
    input_length: u32,
    success: bool,
    output_length: usize,
    error: Option<String>,
}

struct KeyAttempt {
    key_hex: String,
    hit: bool,
}

#[derive(Default)]
struct Options {
    paths: Vec<PathBuf>,
    json: bool,
    no_sha1: bool,
    key_hex: Option<String>,
    key_db: Option<PathBuf>,
    no_key_update: bool,
    out_dir: Option<PathBuf>,
    rounds: u32,
}

fn usage() {
    println!(
        r#"rogos4 - Logos4/LRES01 parser and exporter

Usage:
  rogos4 inspect PATH... [--json] [--no-sha1]
  rogos4 license-inspect PATH... [--json] [--key-db PATH]
  rogos4 legacy-inspect PATH... [--json] [--out DIR]
  rogos4 scan PATH... [--json] [--key HEX] [--key-db PATH] [--rounds 8|12|20]
  rogos4 scan-dir DIR [--json] [--key HEX] [--key-db PATH] [--rounds 8|12|20]
  rogos4 export PATH --out DIR [--key HEX] [--key-db PATH] [--rounds 8|12|20] [--json]

Options:
  --json            JSON output.
  --no-sha1         Skip payload SHA-1 verification.
  --key HEX         Use one 16- or 32-byte key.
  --key-db PATH     Use a specific JSON key database.
  --no-key-update   Do not update the key database.
  --out DIR         Export destination.
  --rounds N        Salsa20 rounds: 8, 12, or 20."#
    );
}

fn require_arg<'a>(args: &'a [String], index: usize, option: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{option} requires a value"))
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        rounds: DEFAULT_ROUNDS,
        ..Options::default()
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => options.json = true,
            "--no-sha1" => options.no_sha1 = true,
            "--key" => {
                i += 1;
                options.key_hex = Some(require_arg(args, i, "--key")?.to_string());
            }
            "--key-db" => {
                i += 1;
                options.key_db = Some(PathBuf::from(require_arg(args, i, "--key-db")?));
            }
            "--no-key-update" => options.no_key_update = true,
            "--out" => {
                i += 1;
                options.out_dir = Some(PathBuf::from(require_arg(args, i, "--out")?));
            }
            "--rounds" => {
                i += 1;
                let value = require_arg(args, i, "--rounds")?;
                options.rounds = value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --rounds value: {value}"))?;
                if !matches!(options.rounds, 8 | 12 | 20) {
                    return Err("--rounds must be 8, 12, or 20".to_string());
                }
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option: {value}"));
            }
            value => options.paths.push(PathBuf::from(value)),
        }
        i += 1;
    }
    if options.paths.is_empty() {
        return Err("at least one path is required".to_string());
    }
    Ok(options)
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, String> {
    util::read_u16_le(bytes, offset)
        .ok_or_else(|| format!("buffer is too short for u16 at 0x{offset:X}"))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, String> {
    util::read_u32_le(bytes, offset)
        .ok_or_else(|| format!("buffer is too short for u32 at 0x{offset:X}"))
}

fn fixed_ascii(bytes: &[u8], offset: usize, length: usize) -> Result<String, String> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| "field offset overflow".to_string())?;
    if end > bytes.len() {
        return Err(format!("buffer is too short for field at 0x{offset:X}"));
    }
    let field = &bytes[offset..end];
    let end = field
        .iter()
        .position(|byte| *byte == 0 || *byte == b'\r' || *byte == b'\n')
        .unwrap_or(field.len());
    Ok(String::from_utf8_lossy(&field[..end])
        .trim_end_matches(' ')
        .to_string())
}

fn parse_lres_header(bytes: &[u8], offset: usize) -> Result<LresHeader, String> {
    let end = offset
        .checked_add(LRES_HEADER_SIZE)
        .ok_or_else(|| "LRES header offset overflow".to_string())?;
    if end > bytes.len() {
        return Err(format!("LRES header at 0x{offset:X} is truncated"));
    }
    if &bytes[offset..offset + MAGIC.len()] != MAGIC {
        return Err(format!("LRES magic is missing at 0x{offset:X}"));
    }
    let header = &bytes[offset..end];
    let mut header_parameter = [0u8; 16];
    header_parameter.copy_from_slice(&header[0x1DC..0x1EC]);
    let mut payload_sha1 = [0u8; 20];
    payload_sha1.copy_from_slice(&header[0x1EC..0x200]);
    Ok(LresHeader {
        offset,
        resource_id: fixed_ascii(header, 0x08, 48)?,
        duplicate_resource_id: fixed_ascii(header, 0x3A, 48)?,
        resource_date: fixed_ascii(header, 0x6C, 20)?,
        driver: fixed_ascii(header, 0x82, 34)?,
        driver_version: fixed_ascii(header, 0xA4, 22)?,
        header_byte_ba: header[0xBA],
        flags: header[0x1CD],
        stored_file_length: read_u32_le(header, 0x1D0)?,
        data_start: read_u32_le(header, 0x1D4)?,
        format_parameter: read_u32_le(header, 0x1D8)?,
        header_parameter,
        payload_sha1,
    })
}

fn find_all(bytes: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > bytes.len() {
        return Vec::new();
    }
    bytes
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, value)| (value == needle).then_some(offset))
        .collect()
}

fn is_license_name(bytes: &[u8]) -> bool {
    let prefixes = [
        b"LLS:".as_slice(),
        b"DB:".as_slice(),
        b"MEDIA:".as_slice(),
        b"RVI:".as_slice(),
        b"WORKFLOW:".as_slice(),
    ];
    bytes.iter().all(|byte| byte.is_ascii_graphic())
        && prefixes.iter().any(|prefix| bytes.starts_with(prefix))
}

fn find_license_record_start(bytes: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    while cursor.checked_add(2)? < bytes.len() {
        let length = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().ok()?) as usize;
        let name_start = cursor + 2;
        let name_end = name_start.checked_add(length)?;
        let key_end = name_end.checked_add(16)?;
        if length > 0
            && length <= 128
            && key_end <= bytes.len()
            && is_license_name(&bytes[name_start..name_end])
        {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn read_license_string(bytes: &[u8], offset: &mut usize) -> Result<String, String> {
    let length = read_u16_le(bytes, *offset)? as usize;
    *offset = offset
        .checked_add(2)
        .ok_or_else(|| "license string offset overflow".to_string())?;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| "license string length overflow".to_string())?;
    if end > bytes.len() {
        return Err(format!("license string at 0x{:X} is truncated", *offset));
    }
    let value = String::from_utf8(bytes[*offset..end].to_vec())
        .map_err(|_| format!("license string at 0x{:X} is not UTF-8", *offset))?;
    *offset = end;
    Ok(value)
}

fn parse_license_records(bytes: &[u8]) -> Result<(String, Vec<LicenseRecord>), String> {
    if bytes.len() < 8 || &bytes[..LICENSE_SECTION_MAGIC.len()] != LICENSE_SECTION_MAGIC {
        return Err("decrypted license payload is missing the inner LSES header".to_string());
    }
    let mut header_offset = 8;
    let _license_guid = read_license_string(bytes, &mut header_offset)?;
    let user_id = read_license_string(bytes, &mut header_offset)?;
    let Some(mut record_offset) = find_license_record_start(bytes, header_offset) else {
        return Err("no resource records found in decrypted license payload".to_string());
    };
    let mut records = Vec::new();
    while record_offset < bytes.len() {
        let name_length = read_u16_le(bytes, record_offset)? as usize;
        let name_start = record_offset + 2;
        let name_end = name_start
            .checked_add(name_length)
            .ok_or_else(|| "license resource name length overflow".to_string())?;
        let key_offset = name_end;
        let key_end = key_offset
            .checked_add(16)
            .ok_or_else(|| "license key length overflow".to_string())?;
        if key_end > bytes.len() || !is_license_name(&bytes[name_start..name_end]) {
            break;
        }
        let resource_id = String::from_utf8_lossy(&bytes[name_start..name_end]).to_string();
        let key_hex = hex_upper(&bytes[key_offset..key_end]);
        let next_offset = find_license_record_start(bytes, key_end);
        let trailing_end = next_offset.unwrap_or(bytes.len());
        let trailing = &bytes[key_end..trailing_end.min(key_end + 32)];
        records.push(LicenseRecord {
            record_offset,
            key_offset,
            resource_id,
            key_hex,
            trailing_hex: hex_upper(trailing),
        });
        let Some(next_offset) = next_offset else {
            break;
        };
        record_offset = next_offset;
    }
    if records.is_empty() {
        return Err("decrypted license payload contains no recognized records".to_string());
    }
    Ok((user_id, records))
}

fn parse_license_container(
    path: &Path,
    key_store: &mut KeyStore,
    update_key_db: bool,
) -> Result<LicenseContainer, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if bytes.len() < 0x44 {
        return Err(format!(
            "{} is shorter than the LIC4/LSES header",
            path.display()
        ));
    }
    if &bytes[..LICENSE_MAGIC.len()] != LICENSE_MAGIC {
        return Err(format!("LIC4 magic is missing in {}", path.display()));
    }
    let format_version = read_u32_le(&bytes, 4)?;
    let declared_payload_length = read_u32_le(&bytes, 8)?;
    let declared_payload_end = 12usize
        .checked_add(declared_payload_length as usize)
        .ok_or_else(|| "LIC4 declared payload length overflows usize".to_string())?;
    let section_offsets = find_all(&bytes, LICENSE_SECTION_MAGIC);
    let prefix_end = section_offsets
        .first()
        .copied()
        .unwrap_or(0x34)
        .min(bytes.len());
    let mut warnings = Vec::new();
    if declared_payload_end != bytes.len() {
        warnings.push(format!(
            "declared payload end 0x{declared_payload_end:X} differs from EOF 0x{:X}",
            bytes.len()
        ));
    }
    if section_offsets.first().copied() != Some(0x34) {
        warnings.push("the first LSES section marker is not at 0x34".to_string());
    }
    if &bytes[0x34..0x3C] != LICENSE_SECTION_MAGIC {
        return Err("the first LSES section is not at 0x34".to_string());
    }
    let nonce: [u8; 8] = bytes[0x3C..0x44]
        .try_into()
        .map_err(|_| "missing LIC4 Salsa20 nonce".to_string())?;
    let mut plaintext = bytes[0x44..].to_vec();
    xor_salsa_range(
        &mut plaintext,
        0,
        key_store.license_master_key(),
        &nonce,
        LICENSE_ROUNDS,
    )?;
    let (user_id, records) = parse_license_records(&plaintext)?;
    let mut unique_keys = Vec::new();
    let mut added_keys = Vec::new();
    for record in &records {
        if !unique_keys.contains(&record.key_hex) {
            unique_keys.push(record.key_hex.clone());
        }
        if update_key_db {
            let key = parse_hex_key(&record.key_hex)?;
            if key_store.add_key(&key) {
                added_keys.push(record.key_hex.clone());
            }
        }
    }
    let key_db_updated = !added_keys.is_empty();
    Ok(LicenseContainer {
        file_size: bytes.len(),
        format_version,
        declared_payload_length,
        declared_payload_end,
        section_offsets,
        nonce_hex: hex_upper(&nonce),
        inner_size: plaintext.len(),
        user_id,
        records,
        unique_keys,
        added_keys,
        key_db_path: key_store.path().display().to_string(),
        key_db_updated,
        header_prefix_hex: hex_upper(&bytes[..prefix_end]),
        file_sha1: sha1_bytes(&bytes),
        warnings,
    })
}

fn inspect_header(
    path: &Path,
    compute_sha1: bool,
) -> Result<(LresHeader, u64, Vec<String>), String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let file_size = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    if file_size < LRES_HEADER_SIZE as u64 {
        return Err(format!(
            "{} is shorter than the 0x200-byte LRES header",
            path.display()
        ));
    }
    let mut header_bytes = vec![0u8; LRES_HEADER_SIZE];
    file.read_exact(&mut header_bytes)
        .map_err(|e| format!("read header {}: {e}", path.display()))?;
    let header = parse_lres_header(&header_bytes, 0)?;
    let mut warnings = Vec::new();
    if header.resource_id != header.duplicate_resource_id {
        warnings.push("resource ID copies at 0x08 and 0x3A differ".to_string());
    }
    if header.stored_file_length as u64 != file_size {
        warnings.push(format!(
            "stored length 0x{:X} differs from actual 0x{:X}",
            header.stored_file_length, file_size
        ));
    }
    if header.data_start as u64 > file_size {
        warnings.push(format!(
            "data_start 0x{:X} is beyond EOF",
            header.data_start
        ));
    }
    if compute_sha1 && header.data_start as u64 <= file_size {
        let computed = sha1_file_range(path, header.data_start as u64)?;
        if !computed.eq_ignore_ascii_case(&hex_upper(&header.payload_sha1)) {
            warnings.push(format!(
                "payload SHA-1 mismatch: header={} actual={computed}",
                hex_upper(&header.payload_sha1)
            ));
        }
    }
    Ok((header, file_size, warnings))
}

fn parse_hex_key(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if text.len() != 32 && text.len() != 64 {
        return Err("key must contain 16 or 32 bytes as hexadecimal".to_string());
    }
    util::parse_hex(text).map_err(|error| error.replace("invalid hex", "invalid key hex"))
}

fn quick_key_hit(bytes: &[u8], key: &[u8], rounds: u32) -> Result<bool, String> {
    if bytes.len() < ENCRYPTED_START + MAGIC.len() {
        return Ok(false);
    }
    let nonce: [u8; 8] = bytes[0x1DC..0x1E4]
        .try_into()
        .map_err(|_| "missing 8-byte Salsa nonce".to_string())?;
    let stream = salsa_block(key, &nonce, (ENCRYPTED_START / 64) as u64, rounds)?;
    let mut decoded = [0u8; 8];
    for index in 0..8 {
        decoded[index] = bytes[ENCRYPTED_START + index] ^ stream[index];
    }
    Ok(&decoded == MAGIC)
}

fn parse_archive(bytes: &[u8], data_start: usize) -> Result<Vec<ArchiveEntry>, String> {
    let count = read_u32_le(bytes, data_start)? as usize;
    if count == 0 || count > 100_000 {
        return Err(format!(
            "archive entry count {count} is outside the safe range"
        ));
    }
    let mut entries = Vec::with_capacity(count);
    let mut record = data_start + 4;
    for _ in 0..count {
        let offset = read_u32_le(bytes, record)?;
        let length = read_u32_le(bytes, record + 4)?;
        let name_length = read_u16_le(bytes, record + 8)? as usize;
        let name_start = record + 10;
        let name_end = name_start
            .checked_add(name_length)
            .ok_or_else(|| "archive name length overflow".to_string())?;
        if name_end > bytes.len() {
            return Err(format!("archive name at 0x{record:X} is truncated"));
        }
        let name = String::from_utf8_lossy(&bytes[name_start..name_end]).to_string();
        let body_end = (offset as usize)
            .checked_add(length as usize)
            .ok_or_else(|| format!("archive body for {name} overflows"))?;
        if body_end > bytes.len() {
            return Err(format!(
                "archive body for {name} is outside the plaintext image: 0x{offset:X}+0x{length:X}"
            ));
        }
        entries.push(ArchiveEntry {
            record_offset: record,
            offset,
            length,
            name,
        });
        record = name_end;
    }
    Ok(entries)
}

fn is_lzma_entry(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".lzma")
}

fn lzma_decompress(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut input = Cursor::new(bytes);
    let mut output = Vec::new();
    lzma_rs::lzma_decompress(&mut input, &mut output)
        .map_err(|error| format!("LZMA decompression failed: {error}"))?;
    Ok(output)
}

fn probe_decompressions(bytes: &[u8], entries: &[ArchiveEntry]) -> Vec<DecompressionProbe> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| is_lzma_entry(&entry.name))
        .map(|(entry_index, entry)| {
            let start = entry.offset as usize;
            let end = start.saturating_add(entry.length as usize);
            if end > bytes.len() {
                return DecompressionProbe {
                    entry_index,
                    name: entry.name.clone(),
                    input_length: entry.length,
                    success: false,
                    output_length: 0,
                    error: Some("entry body is outside the plaintext image".to_string()),
                };
            }
            match lzma_decompress(&bytes[start..end]) {
                Ok(output) => DecompressionProbe {
                    entry_index,
                    name: entry.name.clone(),
                    input_length: entry.length,
                    success: true,
                    output_length: output.len(),
                    error: None,
                },
                Err(error) => DecompressionProbe {
                    entry_index,
                    name: entry.name.clone(),
                    input_length: entry.length,
                    success: false,
                    output_length: 0,
                    error: Some(error),
                },
            }
        })
        .collect()
}

fn xml_entity(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('&') {
        output.push_str(&rest[..start]);
        let Some(end) = rest[start..].find(';') else {
            output.push_str(&rest[start..]);
            return output;
        };
        let entity = &rest[start + 1..start + end];
        let replacement = match entity {
            "amp" => Some("&".to_string()),
            "lt" => Some("<".to_string()),
            "gt" => Some(">".to_string()),
            "quot" => Some("\"".to_string()),
            "apos" => Some("'".to_string()),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                u32::from_str_radix(&entity[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
                    .map(|ch| ch.to_string())
            }
            _ if entity.starts_with('#') => entity[1..]
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .map(|ch| ch.to_string()),
            _ => None,
        };
        if let Some(replacement) = replacement {
            output.push_str(&replacement);
        } else {
            output.push_str(&rest[start..start + end + 1]);
        }
        rest = &rest[start + end + 1..];
    }
    output.push_str(rest);
    output
}

fn xml_path(stack: &[String]) -> String {
    if stack.len() <= 1 {
        "root".to_string()
    } else {
        stack[1..].join(".")
    }
}

fn parse_xml_tag(tag: &str, stack: &[String], fields: &mut Vec<XmlField>) -> (String, bool) {
    let mut cursor = 0;
    while cursor < tag.len() && tag.as_bytes()[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    let name_start = cursor;
    while cursor < tag.len()
        && !tag.as_bytes()[cursor].is_ascii_whitespace()
        && tag.as_bytes()[cursor] != b'/'
    {
        cursor += 1;
    }
    let name = tag[name_start..cursor].to_string();
    let mut attributes = Vec::new();
    while cursor < tag.len() {
        while cursor < tag.len()
            && (tag.as_bytes()[cursor].is_ascii_whitespace() || tag.as_bytes()[cursor] == b'/')
        {
            cursor += 1;
        }
        if cursor >= tag.len() {
            break;
        }
        let attr_start = cursor;
        while cursor < tag.len()
            && !tag.as_bytes()[cursor].is_ascii_whitespace()
            && tag.as_bytes()[cursor] != b'='
        {
            cursor += 1;
        }
        let attr_name = &tag[attr_start..cursor];
        while cursor < tag.len() && tag.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= tag.len() || tag.as_bytes()[cursor] != b'=' {
            break;
        }
        cursor += 1;
        while cursor < tag.len() && tag.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= tag.len() || !matches!(tag.as_bytes()[cursor], b'"' | b'\'') {
            break;
        }
        let quote = tag.as_bytes()[cursor];
        cursor += 1;
        let value_start = cursor;
        while cursor < tag.len() && tag.as_bytes()[cursor] != quote {
            cursor += 1;
        }
        if cursor > tag.len() {
            break;
        }
        attributes.push((attr_name.to_string(), xml_entity(&tag[value_start..cursor])));
        cursor = cursor.saturating_add(1);
    }
    let path = if stack.is_empty() {
        "root".to_string()
    } else {
        let mut path_stack = stack.to_vec();
        path_stack.push(name.clone());
        xml_path(&path_stack)
    };
    for (attribute, value) in attributes {
        fields.push(XmlField {
            kind: "attribute".to_string(),
            path: format!("{path}.@{attribute}"),
            value,
        });
    }
    (name, tag.trim_end().ends_with('/'))
}

fn append_xml_text(fields: &mut Vec<XmlField>, stack: &[String], text: &str, kind: &str) {
    let value = xml_entity(text).trim().to_string();
    if !value.is_empty() && !stack.is_empty() {
        fields.push(XmlField {
            kind: kind.to_string(),
            path: xml_path(stack),
            value,
        });
    }
}

fn parse_xml_fields(bytes: &[u8]) -> Vec<XmlField> {
    let text = String::from_utf8_lossy(bytes);
    let mut fields = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut cursor = 0;
    while cursor < text.len() {
        let Some(relative) = text[cursor..].find('<') else {
            append_xml_text(&mut fields, &stack, &text[cursor..], "text");
            break;
        };
        let tag_start = cursor + relative;
        append_xml_text(&mut fields, &stack, &text[cursor..tag_start], "text");
        if text[tag_start..].starts_with("<!--") {
            if let Some(end) = text[tag_start + 4..].find("-->") {
                cursor = tag_start + 7 + end;
                continue;
            }
            break;
        }
        if text[tag_start..].starts_with("<![CDATA[") {
            if let Some(end) = text[tag_start + 9..].find("]]>") {
                append_xml_text(
                    &mut fields,
                    &stack,
                    &text[tag_start + 9..tag_start + 9 + end],
                    "cdata",
                );
                cursor = tag_start + 12 + end;
                continue;
            }
            break;
        }
        let Some(relative_end) = text[tag_start..].find('>') else {
            break;
        };
        let tag_end = tag_start + relative_end;
        let raw = &text[tag_start + 1..tag_end];
        if let Some(close_name) = raw.strip_prefix('/') {
            let close_name = close_name.trim();
            if !stack.is_empty() {
                let _ = close_name;
                stack.pop();
            }
        } else if !raw.starts_with('?') && !raw.starts_with('!') {
            let (name, self_closing) = parse_xml_tag(raw, &stack, &mut fields);
            stack.push(name);
            if self_closing {
                stack.pop();
            }
        }
        cursor = tag_end + 1;
    }
    let mut current_semantic_names: HashMap<String, String> = HashMap::new();
    for field in &mut fields {
        if field.kind == "attribute" && field.path.ends_with(".@name") {
            let base = field.path.trim_end_matches(".@name").to_string();
            current_semantic_names.insert(base, field.value.clone());
        } else if field.kind != "attribute" {
            if let Some(name) = current_semantic_names.get(&field.path) {
                field.path = if field.path.ends_with(".dc-element") {
                    name.clone()
                } else if field.path.ends_with(".citation-field") {
                    format!("citation.{name}")
                } else {
                    name.clone()
                };
            }
        }
    }
    fields
}

fn safe_component(value: &str) -> String {
    let mut output = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '@') {
            output.push(ch);
        } else {
            output.push('_');
        }
    }
    if output.is_empty() {
        "entry".to_string()
    } else {
        output
    }
}

fn safe_entry_path(root: &Path, name: &str, index: usize) -> PathBuf {
    let mut output = root.to_path_buf();
    let mut component_count = 0;
    for component in name.split(['/', '\\']) {
        if component.is_empty() || component == "." || component == ".." {
            continue;
        }
        output.push(safe_component(component));
        component_count += 1;
    }
    if component_count == 0 {
        output.push(format!("entry-{index:04}.bin"));
    }
    output
}

fn candidate_keys(
    options: &Options,
    key_store: Option<&KeyStore>,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    if let Some(key_hex) = &options.key_hex {
        let key = parse_hex_key(key_hex)?;
        return Ok(vec![(hex_upper(&key), key)]);
    }
    let key_store = key_store
        .ok_or_else(|| "a JSON key database is required unless --key is supplied".to_string())?;
    key_store
        .keys()
        .iter()
        .map(|entry| Ok((entry.key_hex.clone(), entry.key.clone())))
        .collect()
}

fn parse_embedded_legacy(
    plaintext: &[u8],
    entries: &[ArchiveEntry],
) -> (Vec<legacy::LegacyInfo>, Vec<String>) {
    let mut resources = Vec::new();
    let mut warnings = Vec::new();
    for entry in entries {
        let extension = Path::new(&entry.name)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if !extension.eq_ignore_ascii_case("lsf") && !extension.eq_ignore_ascii_case("lix") {
            continue;
        }
        let start = entry.offset as usize;
        let Some(end) = start.checked_add(entry.length as usize) else {
            warnings.push(format!("{}: legacy entry offset overflows", entry.name));
            continue;
        };
        let Some(bytes) = plaintext.get(start..end) else {
            warnings.push(format!(
                "{}: legacy entry is outside the decoded resource",
                entry.name
            ));
            continue;
        };
        let source = format!("{} @0x{:X}", entry.name, entry.offset);
        match legacy::parse_bytes(&source, bytes) {
            Ok(info) => resources.push(info),
            Err(error) => warnings.push(format!("{}: {error}", entry.name)),
        }
    }
    (resources, warnings)
}

fn decode_with_key(
    path: &Path,
    bytes: Vec<u8>,
    key_hex: &str,
    key: &[u8],
    rounds: u32,
) -> Result<DecodedResource, String> {
    let outer = parse_lres_header(&bytes, 0)?;
    if !quick_key_hit(&bytes, key, rounds)? {
        return Err("candidate key does not decrypt the nested LRES magic".to_string());
    }
    let nonce: [u8; 8] = outer.header_parameter[..8].try_into().unwrap();
    let mut plaintext = bytes;
    xor_salsa_range(&mut plaintext, ENCRYPTED_START, key, &nonce, rounds)?;
    let inner_offset = ENCRYPTED_START;
    let inner = parse_lres_header(&plaintext, inner_offset)?;
    let data_start = outer.data_start as usize;
    let entries = parse_archive(&plaintext, data_start)?;
    let decompressions = probe_decompressions(&plaintext, &entries);
    let (legacy, legacy_warnings) = parse_embedded_legacy(&plaintext, &entries);
    let metadata_entry = entries
        .iter()
        .position(|entry| entry.name.eq_ignore_ascii_case("this.metadata.xml"));
    let mut warnings = Vec::new();
    if inner.resource_id != outer.resource_id {
        warnings.push("nested LRES resource ID differs from outer header".to_string());
    }
    if entries.is_empty() {
        warnings.push("archive directory is empty".to_string());
    }
    for probe in &decompressions {
        if let Some(error) = &probe.error {
            warnings.push(format!("{}: {error}", probe.name));
        }
    }
    warnings.extend(legacy_warnings);
    let fields = if let Some(index) = metadata_entry {
        let entry = &entries[index];
        let start = entry.offset as usize;
        let end = start + entry.length as usize;
        if !plaintext[start..end].starts_with(b"<?xml")
            && !plaintext[start..end].starts_with(b"\xEF\xBB\xBF<?xml")
        {
            warnings.push("this.metadata.xml does not start with XML".to_string());
        }
        parse_xml_fields(&plaintext[start..end])
    } else {
        warnings.push("archive has no this.metadata.xml entry".to_string());
        Vec::new()
    };
    Ok(DecodedResource {
        path: path.display().to_string(),
        key_hex: key_hex.to_string(),
        outer,
        inner,
        plaintext,
        entries,
        metadata_entry,
        fields,
        decompressions,
        legacy,
        warnings,
    })
}

fn read_prefix(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut bytes = vec![0u8; ENCRYPTED_START + MAGIC.len()];
    file.read_exact(&mut bytes)
        .map_err(|e| format!("read prefix {}: {e}", path.display()))?;
    Ok(bytes)
}

fn try_decode(
    path: &Path,
    options: &Options,
    key_store: Option<&KeyStore>,
) -> Result<(Vec<KeyAttempt>, DecodedResource), String> {
    let prefix = read_prefix(path)?;
    let candidates = candidate_keys(options, key_store)?;
    let mut attempts = Vec::new();
    let mut hit: Option<(String, Vec<u8>)> = None;
    for (hex, key) in candidates {
        let matches = quick_key_hit(&prefix, &key, options.rounds)?;
        attempts.push(KeyAttempt {
            key_hex: hex.clone(),
            hit: matches,
        });
        if matches && hit.is_none() {
            hit = Some((hex, key));
        }
    }
    let Some((hex, key)) = hit else {
        return Err("none of the candidate keys produced nested LRES01\\r\\n".to_string());
    };
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let decoded = decode_with_key(path, bytes, &hex, &key, options.rounds)?;
    Ok((attempts, decoded))
}

fn title_from_fields(fields: &[XmlField]) -> Option<String> {
    for target in ["header.title", "dc.title", "citation.bt"] {
        if let Some(field) = fields
            .iter()
            .find(|field| field.kind != "attribute" && field.path == target)
        {
            return Some(field.value.clone());
        }
    }
    None
}

fn authors_from_fields(fields: &[XmlField]) -> String {
    if let Some(field) = fields
        .iter()
        .find(|field| field.kind != "attribute" && field.path == "citation.au")
    {
        return field.value.clone();
    }
    let mut values = Vec::new();
    for field in fields
        .iter()
        .filter(|field| field.kind != "attribute" && field.path == "dc.creator.personalname")
    {
        if !values.contains(&field.value) {
            values.push(field.value.clone());
        }
    }
    values.join("; ")
}

fn json_header(header: &LresHeader) -> String {
    format!(
        "{{\"offset\":{},\"resource_id\":{},\"duplicate_resource_id\":{},\"resource_date\":{},\"driver\":{},\"driver_version\":{},\"header_byte_ba\":{},\"flags\":{},\"stored_file_length\":{},\"data_start\":{},\"format_parameter\":{},\"header_parameter\":{},\"payload_sha1\":{}}}",
        header.offset,
        json_string(&header.resource_id),
        json_string(&header.duplicate_resource_id),
        json_string(&header.resource_date),
        json_string(&header.driver),
        json_string(&header.driver_version),
        header.header_byte_ba,
        header.flags,
        header.stored_file_length,
        header.data_start,
        header.format_parameter,
        json_string(&hex_upper(&header.header_parameter)),
        json_string(&hex_upper(&header.payload_sha1)),
    )
}

fn json_license(container: &LicenseContainer) -> String {
    format!(
        "{{\"file_size\":{},\"magic\":\"LIC4\",\"format_version\":{},\"declared_payload_length\":{},\"declared_payload_end\":{},\"section_offsets\":[{}],\"nonce_hex\":{},\"inner_size\":{},\"user_id\":{},\"records\":[{}],\"unique_keys\":[{}],\"added_keys\":[{}],\"key_db_path\":{},\"key_db_updated\":{},\"header_prefix_hex\":{},\"file_sha1\":{},\"warnings\":[{}]}}",
        container.file_size,
        container.format_version,
        container.declared_payload_length,
        container.declared_payload_end,
        container
            .section_offsets
            .iter()
            .map(|offset| format!("{offset}"))
            .collect::<Vec<_>>()
            .join(","),
        json_string(&container.nonce_hex),
        container.inner_size,
        json_string(&container.user_id),
        container
            .records
            .iter()
            .map(|record| {
                format!(
                    "{{\"record_offset\":{},\"key_offset\":{},\"resource_id\":{},\"key_hex\":{},\"trailing_hex\":{}}}",
                    record.record_offset,
                    record.key_offset,
                    json_string(&record.resource_id),
                    json_string(&record.key_hex),
                    json_string(&record.trailing_hex)
                )
            })
            .collect::<Vec<_>>()
            .join(","),
        container
            .unique_keys
            .iter()
            .map(|key| json_string(key))
            .collect::<Vec<_>>()
            .join(","),
        container
            .added_keys
            .iter()
            .map(|key| json_string(key))
            .collect::<Vec<_>>()
            .join(","),
        json_string(&container.key_db_path),
        container.key_db_updated,
        json_string(&container.header_prefix_hex),
        json_string(&container.file_sha1),
        container
            .warnings
            .iter()
            .map(|warning| json_string(warning))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn json_fields(fields: &[XmlField]) -> String {
    fields
        .iter()
        .map(|field| {
            format!(
                "{{\"kind\":{},\"path\":{},\"value\":{}}}",
                json_string(&field.kind),
                json_string(&field.path),
                json_string(&field.value)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn json_entries(entries: &[ArchiveEntry]) -> String {
    entries
        .iter()
        .map(|entry| {
            format!(
                "{{\"record_offset\":{},\"offset\":{},\"length\":{},\"name\":{}}}",
                entry.record_offset,
                entry.offset,
                entry.length,
                json_string(&entry.name)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn json_decompressions(probes: &[DecompressionProbe]) -> String {
    probes
        .iter()
        .map(|probe| {
            format!(
                "{{\"entry_index\":{},\"name\":{},\"input_length\":{},\"success\":{},\"output_length\":{},\"error\":{}}}",
                probe.entry_index,
                json_string(&probe.name),
                probe.input_length,
                probe.success,
                probe.output_length,
                probe
                    .error
                    .as_deref()
                    .map(json_string)
                    .unwrap_or_else(|| "null".to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn json_legacy(resources: &[legacy::LegacyInfo]) -> String {
    resources
        .iter()
        .map(legacy::json)
        .collect::<Vec<_>>()
        .join(",")
}

fn inspect_human(path: &Path, header: &LresHeader, file_size: u64, warnings: &[String]) {
    println!("path                 {}", path.display());
    println!("file_size            {}", file_size);
    println!("header_offset        0x{:X}", header.offset);
    println!("magic                LRES01\\r\\n");
    println!("resource_id          {}", header.resource_id);
    println!("duplicate_id         {}", header.duplicate_resource_id);
    println!("resource_date        {}", header.resource_date);
    println!("driver               {}", header.driver);
    println!("driver_version       {}", header.driver_version);
    println!("header[0xBA]         0x{:02X}", header.header_byte_ba);
    println!("flags                0x{:02X}", header.flags);
    println!("stored_file_length   0x{:X}", header.stored_file_length);
    println!("data_start           0x{:X}", header.data_start);
    println!(
        "format_parameter     {} (0x{:X})",
        header.format_parameter, header.format_parameter
    );
    println!(
        "header[0x1DC..1EC]   {}",
        hex_upper(&header.header_parameter)
    );
    println!("payload_sha1_header  {}", hex_upper(&header.payload_sha1));
    for warning in warnings {
        println!("warning              {warning}");
    }
}

fn license_inspect_human(path: &Path, container: &LicenseContainer) {
    println!("path                         {}", path.display());
    println!("file_size                    {}", container.file_size);
    println!("magic                        LIC4");
    println!("format_version              {}", container.format_version);
    println!(
        "declared_payload_length     0x{:X}",
        container.declared_payload_length
    );
    println!(
        "declared_payload_end        0x{:X}",
        container.declared_payload_end
    );
    let section_offsets = container
        .section_offsets
        .iter()
        .map(|offset| format!("0x{offset:X}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("LSES_offsets                {section_offsets}");
    println!("nonce                       {}", container.nonce_hex);
    println!("inner_size                  {}", container.inner_size);
    println!("user_id                     {}", container.user_id);
    println!("license_records             {}", container.records.len());
    println!(
        "unique_keys                 {}",
        container.unique_keys.len()
    );
    println!("added_keys                  {}", container.added_keys.len());
    println!("key_db                      {}", container.key_db_path);
    println!("key_db_updated              {}", container.key_db_updated);
    println!(
        "header_prefix_hex           {}",
        container.header_prefix_hex
    );
    println!("file_sha1                   {}", container.file_sha1);
    for record in &container.records {
        println!(
            "  {:<28} {} @0x{:X}",
            record.resource_id, record.key_hex, record.key_offset
        );
    }
    for warning in &container.warnings {
        println!("warning                     {warning}");
    }
}

fn scan_json(
    path: &Path,
    attempts: &[KeyAttempt],
    decoded: Option<&DecodedResource>,
    error: Option<&str>,
) -> String {
    let attempts = attempts
        .iter()
        .map(|attempt| {
            format!(
                "{{\"key_hex\":{},\"hit\":{}}}",
                json_string(&attempt.key_hex),
                attempt.hit,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let decoded_json = decoded
        .map(|value| {
            format!(
                "{{\"key_hex\":{},\"inner_header\":{},\"archive_count\":{},\"title\":{},\"authors\":{},\"fields\":[{}],\"decompressions\":[{}],\"legacy\":[{}],\"warnings\":[{}]}}",
                json_string(&value.key_hex),
                json_header(&value.inner),
                value.entries.len(),
                value.title_json(),
                json_string(&authors_from_fields(&value.fields)),
                json_fields(&value.fields),
                json_decompressions(&value.decompressions),
                json_legacy(&value.legacy),
                value
                    .warnings
                    .iter()
                    .map(|warning| json_string(warning))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .unwrap_or_else(|| "null".to_string());
    format!(
        "{{\"path\":{},\"attempts\":[{}],\"decoded\":{},\"error\":{}}}",
        json_string(&path.display().to_string()),
        attempts,
        decoded_json,
        error.map(json_string).unwrap_or_else(|| "null".to_string())
    )
}

impl DecodedResource {
    fn title_json(&self) -> String {
        title_from_fields(&self.fields)
            .as_deref()
            .map(json_string)
            .unwrap_or_else(|| "null".to_string())
    }

    fn human_summary(&self) {
        println!("  key_hex              {}", self.key_hex);
        println!("  inner_resource_id    {}", self.inner.resource_id);
        println!("  archive_entries      {}", self.entries.len());
        println!("  lzma_entries         {}", self.decompressions.len());
        println!("  legacy_entries       {}", self.legacy.len());
        for resource in &self.legacy {
            println!(
                "  legacy               {} {} ({} blocks, {} titles)",
                resource.kind,
                resource.path,
                resource.blocks.len(),
                resource.titles.len()
            );
        }
        for probe in &self.decompressions {
            if probe.success {
                println!(
                    "  lzma_ok              {} ({} -> {} bytes)",
                    probe.name, probe.input_length, probe.output_length
                );
            } else if let Some(error) = &probe.error {
                println!("  lzma_error           {} ({error})", probe.name);
            }
        }
        if let Some(title) = title_from_fields(&self.fields) {
            println!("  title                {title}");
        }
        let authors = authors_from_fields(&self.fields);
        if !authors.is_empty() {
            println!("  authors              {authors}");
        }
        if let Some(index) = self.metadata_entry {
            let entry = &self.entries[index];
            println!(
                "  metadata             0x{:X} ({} bytes)",
                entry.offset, entry.length
            );
        }
        for warning in &self.warnings {
            println!("  warning              {warning}");
        }
    }
}

fn export_decoded(decoded: &DecodedResource, root: &Path) -> Result<(), String> {
    fs::create_dir_all(root).map_err(|e| format!("create {}: {e}", root.display()))?;
    fs::write(root.join("logos4.plain"), &decoded.plaintext)
        .map_err(|e| format!("write plaintext image: {e}"))?;
    let entries_root = root.join("entries");
    fs::create_dir_all(&entries_root)
        .map_err(|e| format!("create {}: {e}", entries_root.display()))?;
    for (index, entry) in decoded.entries.iter().enumerate() {
        let destination = safe_entry_path(&entries_root, &entry.name, index);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let start = entry.offset as usize;
        let end = start + entry.length as usize;
        fs::write(&destination, &decoded.plaintext[start..end])
            .map_err(|e| format!("write {}: {e}", destination.display()))?;
    }
    for probe in &decoded.decompressions {
        if !probe.success {
            continue;
        }
        let entry = &decoded.entries[probe.entry_index];
        let start = entry.offset as usize;
        let end = start + entry.length as usize;
        let output = lzma_decompress(&decoded.plaintext[start..end])?;
        let decompressed_root = root.join("decompressed");
        let destination = safe_entry_path(
            &decompressed_root,
            &format!("{}.decompressed", entry.name),
            probe.entry_index,
        );
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        fs::write(&destination, output)
            .map_err(|e| format!("write {}: {e}", destination.display()))?;
    }
    let manifest = format!(
        "{{\"source\":{},\"key_hex\":{},\"outer_header\":{},\"inner_header\":{},\"archive_entries\":[{}],\"metadata_entry\":{},\"fields\":[{}],\"decompressions\":[{}],\"legacy\":[{}],\"warnings\":[{}]}}\n",
        json_string(&decoded.path),
        json_string(&decoded.key_hex),
        json_header(&decoded.outer),
        json_header(&decoded.inner),
        json_entries(&decoded.entries),
        decoded
            .metadata_entry
            .map(|value| value.to_string())
            .unwrap_or_else(|| "null".to_string()),
        json_fields(&decoded.fields),
        json_decompressions(&decoded.decompressions),
        json_legacy(&decoded.legacy),
        decoded
            .warnings
            .iter()
            .map(|warning| json_string(warning))
            .collect::<Vec<_>>()
            .join(",")
    );
    if !decoded.legacy.is_empty() {
        let legacy_root = root.join("legacy");
        for (index, resource) in decoded.legacy.iter().enumerate() {
            let stem = format!("{index:04}-{}", safe_component(&resource.kind));
            legacy::export(resource, &legacy_root, &stem)?;
        }
    }
    fs::write(root.join("manifest.json"), manifest).map_err(|e| format!("write manifest: {e}"))?;
    if let Some(index) = decoded.metadata_entry {
        let entry = &decoded.entries[index];
        let start = entry.offset as usize;
        let end = start + entry.length as usize;
        fs::write(
            root.join("this.metadata.xml"),
            &decoded.plaintext[start..end],
        )
        .map_err(|e| format!("write metadata XML: {e}"))?;
    }
    Ok(())
}

fn collect_logos4_files(root: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|e| format!("read {}: {e}", root.display()))? {
        let path = entry
            .map_err(|e| format!("read directory entry: {e}"))?
            .path();
        if path.is_dir() {
            collect_logos4_files(&path, output)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("logos4"))
        {
            output.push(path);
        }
    }
    Ok(())
}

fn command_inspect(options: Options) -> Result<(), String> {
    let mut json_results = Vec::new();
    for path in &options.paths {
        let (header, file_size, warnings) = inspect_header(path, !options.no_sha1)?;
        if options.json {
            json_results.push(format!(
                "{{\"path\":{},\"file_size\":{},\"header\":{},\"warnings\":[{}]}}",
                json_string(&path.display().to_string()),
                file_size,
                json_header(&header),
                warnings
                    .iter()
                    .map(|warning| json_string(warning))
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        } else {
            inspect_human(path, &header, file_size, &warnings);
            if options.paths.len() > 1 {
                println!();
            }
        }
    }
    if options.json {
        println!("[{}]", json_results.join(","));
    }
    Ok(())
}

fn command_license_inspect(options: Options) -> Result<(), String> {
    let mut key_store = KeyStore::load(options.key_db.as_deref())?;
    let mut results = Vec::new();
    for path in &options.paths {
        results.push((
            path.clone(),
            parse_license_container(path, &mut key_store, !options.no_key_update),
        ));
    }
    key_store.save_if_dirty()?;
    let mut json_results = Vec::new();
    for (path, result) in results {
        match result {
            Ok(container) => {
                if options.json {
                    json_results.push(format!(
                        "{{\"path\":{},\"license\":{}}}",
                        json_string(&path.display().to_string()),
                        json_license(&container)
                    ));
                } else {
                    license_inspect_human(&path, &container);
                    if options.paths.len() > 1 {
                        println!();
                    }
                }
            }
            Err(error) => {
                if options.json {
                    json_results.push(format!(
                        "{{\"path\":{},\"license\":null,\"error\":{}}}",
                        json_string(&path.display().to_string()),
                        json_string(&error)
                    ));
                } else {
                    println!("{}", path.display());
                    println!("  error                       {error}");
                }
            }
        }
    }
    if options.json {
        println!("[{}]", json_results.join(","));
    }
    Ok(())
}

fn command_legacy_inspect(options: Options) -> Result<(), String> {
    let mut json_results = Vec::new();
    for (index, path) in options.paths.iter().enumerate() {
        match legacy::parse_file(path) {
            Ok(info) => {
                if let Some(root) = options.out_dir.as_deref() {
                    let stem = format!("{index:04}-{}", safe_component(&info.kind));
                    legacy::export(&info, root, &stem)?;
                }
                if options.json {
                    json_results.push(legacy::json(&info));
                } else {
                    legacy::human(&info);
                    if options.paths.len() > 1 {
                        println!();
                    }
                }
            }
            Err(error) => {
                if options.json {
                    json_results.push(format!(
                        "{{\"path\":{},\"legacy\":null,\"error\":{}}}",
                        json_string(&path.display().to_string()),
                        json_string(&error)
                    ));
                } else {
                    println!("{}", path.display());
                    println!("  error                       {error}");
                }
            }
        }
    }
    if options.json {
        println!("[{}]", json_results.join(","));
    }
    Ok(())
}

fn command_scan(options: Options) -> Result<(), String> {
    let key_store = if options.key_hex.is_none() {
        Some(KeyStore::load(options.key_db.as_deref())?)
    } else {
        None
    };
    let mut json_results = Vec::new();
    for path in &options.paths {
        let result = try_decode(path, &options, key_store.as_ref());
        match result {
            Ok((attempts, decoded)) => {
                if options.json {
                    json_results.push(scan_json(path, &attempts, Some(&decoded), None));
                } else {
                    println!("{}", path.display());
                    let hit_count = attempts.iter().filter(|attempt| attempt.hit).count();
                    println!("  key_hits             {hit_count}");
                    decoded.human_summary();
                }
            }
            Err(error) => {
                if options.json {
                    json_results.push(scan_json(path, &[], None, Some(&error)));
                } else {
                    println!("{}", path.display());
                    println!("  key_hits             0");
                    println!("  error                {error}");
                }
            }
        }
    }
    if options.json {
        println!("[{}]", json_results.join(","));
    }
    Ok(())
}

fn command_scan_dir(mut options: Options) -> Result<(), String> {
    if options.paths.len() != 1 {
        return Err("scan-dir accepts exactly one directory".to_string());
    }
    let root = options.paths.remove(0);
    let mut paths = Vec::new();
    collect_logos4_files(&root, &mut paths)?;
    paths.sort();
    if paths.is_empty() {
        return Err(format!("no .logos4 files found under {}", root.display()));
    }
    options.paths = paths;
    command_scan(options)
}

fn command_export(options: Options) -> Result<(), String> {
    if options.paths.len() != 1 {
        return Err("export accepts exactly one resource path".to_string());
    }
    let root = options
        .out_dir
        .as_deref()
        .ok_or_else(|| "export requires --out DIR".to_string())?;
    let path = &options.paths[0];
    let key_store = if options.key_hex.is_none() {
        Some(KeyStore::load(options.key_db.as_deref())?)
    } else {
        None
    };
    let (attempts, decoded) = try_decode(path, &options, key_store.as_ref())?;
    export_decoded(&decoded, root)?;
    if options.json {
        println!("{}", scan_json(path, &attempts, Some(&decoded), None));
    } else {
        println!("exported {}", path.display());
        decoded.human_summary();
        println!("  output               {}", root.display());
        println!("  files                logos4.plain, manifest.json, entries/, decompressed/, legacy/, this.metadata.xml");
    }
    Ok(())
}

fn main() {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        usage();
        return;
    }
    let command = args.remove(0);
    let result = match parse_options(&args) {
        Ok(options) => match command.as_str() {
            "inspect" => command_inspect(options),
            "license-inspect" => command_license_inspect(options),
            "legacy-inspect" => command_legacy_inspect(options),
            "scan" => command_scan(options),
            "scan-dir" => command_scan_dir(options),
            "export" => command_export(options),
            other => Err(format!("unknown command: {other}")),
        },
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        eprintln!("run with --help for usage");
        std::process::exit(2);
    }
}
