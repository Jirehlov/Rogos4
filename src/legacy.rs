use std::fs;
use std::path::Path;

use crate::util::{json_string, read_u16_le, read_u32_le};

#[derive(Clone)]
pub struct LegacyBlock {
    pub descriptor_offset: usize,
    pub tag: String,
    pub flags: u32,
    pub offset: u32,
    pub length: u32,
}

struct U32Summary {
    count: usize,
    min: u32,
    max: u32,
    monotonic: bool,
    permutation: bool,
    first: Vec<u32>,
    last: Vec<u32>,
}

struct TextCandidate {
    offset: usize,
    encoding: String,
    length: usize,
    text: String,
}

struct TartAnalysis {
    type_11_count: usize,
    type_12_count: usize,
    candidates: Vec<TextCandidate>,
    text_fragment_count: usize,
    text_length: usize,
    plain_text: String,
}

pub struct LegacyInfo {
    pub path: String,
    pub file_size: usize,
    pub kind: String,
    pub declared_size: u32,
    pub blocks: Vec<LegacyBlock>,
    pub titles: Vec<String>,
    pub plain_text: String,
    ccct: Option<U32Summary>,
    coff: Option<U32Summary>,
    tart: Option<TartAnalysis>,
    pub warnings: Vec<String>,
}

pub fn parse_file(path: &Path) -> Result<LegacyInfo, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    parse_bytes(&path.display().to_string(), &bytes)
}

pub fn parse_bytes(path: &str, bytes: &[u8]) -> Result<LegacyInfo, String> {
    if bytes.len() < 0x80 {
        return Err("LSF/LIX file is shorter than the legacy header".to_string());
    }
    if &bytes[..4] != b"LSFF" {
        return Err("LSF/LIX magic LSFF is missing".to_string());
    }
    let kind_bytes = &bytes[8..12];
    let kind = String::from_utf8_lossy(kind_bytes).to_string();
    if kind != "GTTL" && kind != "BIDX" {
        return Err(format!("unsupported LSFF payload kind {kind:?}"));
    }
    let declared_size = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let blocks = parse_blocks(bytes);
    if blocks.is_empty() {
        return Err("no valid legacy directory blocks were found".to_string());
    }
    let mut warnings = Vec::new();
    if declared_size as usize + 8 != bytes.len() {
        warnings.push(format!(
            "header size field is {}, file size is {}",
            declared_size + 8,
            bytes.len()
        ));
    }
    if !blocks.iter().any(|block| block.tag == "fver") {
        warnings.push("directory has no fver block".to_string());
    }
    let titles = if kind == "BIDX" {
        blocks
            .iter()
            .filter(|block| block.tag == "klst")
            .find_map(|block| block_bytes(bytes, block).map(parse_title_list))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let ccct = if kind == "BIDX" {
        blocks
            .iter()
            .find(|block| block.tag == "ccct")
            .and_then(|block| block_bytes(bytes, block))
            .and_then(parse_u32_summary)
    } else {
        None
    };
    let coff = if kind == "BIDX" {
        blocks
            .iter()
            .find(|block| block.tag == "coff")
            .and_then(|block| block_bytes(bytes, block))
            .and_then(parse_u32_summary)
    } else {
        None
    };
    let tart = if kind == "GTTL" {
        blocks
            .iter()
            .find(|block| block.tag == "tart")
            .and_then(|block| {
                block_bytes(bytes, block)
                    .map(|block_bytes| analyze_tart(block_bytes, block.offset as usize))
            })
    } else {
        None
    };
    let plain_text = tart
        .as_ref()
        .map(|analysis| analysis.plain_text.clone())
        .unwrap_or_else(|| titles.join("\n"));
    if kind == "GTTL" && !blocks.iter().any(|block| block.tag == "tart") {
        warnings.push("GTTL resource has no tart article block".to_string());
    }
    if kind == "BIDX" && !blocks.iter().any(|block| block.tag == "ccct") {
        warnings.push("BIDX resource has no ccct cumulative-count block".to_string());
    }
    Ok(LegacyInfo {
        path: path.to_string(),
        file_size: bytes.len(),
        kind,
        declared_size,
        blocks,
        titles,
        plain_text,
        ccct,
        coff,
        tart,
        warnings,
    })
}

fn is_tag(bytes: &[u8]) -> bool {
    bytes.len() == 4
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn parse_blocks(bytes: &[u8]) -> Vec<LegacyBlock> {
    let scan_end = bytes.len().min(0x400);
    let mut candidates = Vec::new();
    for descriptor_offset in 0x70..scan_end.saturating_sub(15) {
        let Some(tag_bytes) = bytes.get(descriptor_offset..descriptor_offset + 4) else {
            continue;
        };
        if !is_tag(tag_bytes) {
            continue;
        }
        let Some(flags) = read_u32_le(bytes, descriptor_offset + 4) else {
            continue;
        };
        let Some(length) = read_u32_le(bytes, descriptor_offset + 8) else {
            continue;
        };
        let Some(offset) = read_u32_le(bytes, descriptor_offset + 12) else {
            continue;
        };
        let Some(end) = (offset as usize).checked_add(length as usize) else {
            continue;
        };
        if flags != 0
            || offset as usize <= descriptor_offset + 16
            || length == 0
            || end < offset as usize
            || end > bytes.len()
        {
            continue;
        }
        candidates.push(LegacyBlock {
            descriptor_offset,
            tag: String::from_utf8_lossy(tag_bytes).to_string(),
            flags,
            offset,
            length,
        });
    }
    let Some(first_data_offset) = candidates.iter().map(|block| block.offset as usize).min() else {
        return Vec::new();
    };
    candidates.retain(|block| block.descriptor_offset < first_data_offset);
    candidates.sort_by_key(|block| block.descriptor_offset);
    candidates.dedup_by_key(|block| block.descriptor_offset);
    candidates
}

fn block_bytes<'a>(bytes: &'a [u8], block: &LegacyBlock) -> Option<&'a [u8]> {
    let start = block.offset as usize;
    let end = start.checked_add(block.length as usize)?;
    bytes.get(start..end)
}

fn parse_title_list(bytes: &[u8]) -> Vec<String> {
    let mut titles = Vec::new();
    let mut offset = 0;
    while let Some(length) = read_u16_le(bytes, offset) {
        offset += 2;
        let byte_length = length as usize * 2;
        if length == 0 || offset.checked_add(byte_length).is_none() {
            break;
        }
        let end = offset + byte_length;
        if end > bytes.len() {
            break;
        }
        let units = bytes[offset..end]
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes(unit.try_into().unwrap()))
            .collect::<Vec<_>>();
        let title = String::from_utf16_lossy(&units);
        if title.is_empty() {
            break;
        }
        titles.push(title);
        offset = end;
        if bytes.get(offset..offset + 2) == Some(&[0, 0]) {
            offset += 2;
        }
    }
    titles
}

fn parse_u32_summary(bytes: &[u8]) -> Option<U32Summary> {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let values = bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>();
    let min = *values.iter().min()?;
    let max = *values.iter().max()?;
    let monotonic = values.windows(2).all(|window| window[0] <= window[1]);
    let permutation = values.len() == (max as usize + 1)
        && values.iter().enumerate().all(|(index, value)| {
            *value as usize == index
                || (*value as usize) < values.len()
                    && values
                        .iter()
                        .filter(|candidate| **candidate == *value)
                        .count()
                        == 1
        });
    Some(U32Summary {
        count: values.len(),
        min,
        max,
        monotonic,
        permutation,
        first: values.iter().take(10).copied().collect(),
        last: values
            .iter()
            .rev()
            .take(10)
            .copied()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect(),
    })
}

fn preview(text: &str) -> String {
    let mut output = text
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    output = output.split_whitespace().collect::<Vec<_>>().join(" ");
    if output.chars().count() > 180 {
        output.chars().take(180).collect::<String>() + "..."
    } else {
        output
    }
}

fn is_ascii_text_byte(byte: u8) -> bool {
    byte == b'\t' || byte == b'\r' || byte == b'\n' || (0x20..=0x7E).contains(&byte)
}

fn is_utf16_text_unit(bytes: &[u8], offset: usize) -> bool {
    bytes
        .get(offset..offset + 2)
        .is_some_and(|unit| unit[1] == 0 && is_ascii_text_byte(unit[0]))
}

fn normalize_text(value: &str) -> Option<String> {
    let text = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.len() < 4
        || (text.len() < 12 && !text.chars().any(char::is_whitespace))
        || text.starts_with("=d~")
        || text.contains('\u{FFFD}')
    {
        return None;
    }
    let alphabetic = text.chars().filter(|ch| ch.is_alphabetic()).count();
    if alphabetic < 2 || (text.len() < 8 && !text.chars().next()?.is_alphabetic()) {
        return None;
    }
    let punctuation = text
        .chars()
        .filter(|ch| !ch.is_alphanumeric() && !ch.is_whitespace())
        .count();
    if text.len() < 12 && punctuation > 0 {
        return None;
    }
    if punctuation > (text.len() / 16).max(1) {
        return None;
    }
    let normal_word = text.split_whitespace().any(|word| {
        let mut chars = word.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        let rest = chars.collect::<Vec<_>>();
        rest.len() >= 3
            && first.is_alphabetic()
            && rest.iter().all(|ch| ch.is_lowercase())
            && word.chars().all(|ch| ch.is_alphabetic())
    });
    if !normal_word {
        return None;
    }
    Some(text)
}

fn make_text_candidate(offset: usize, encoding: &str, text: &str) -> Option<TextCandidate> {
    let text = normalize_text(text)?;
    Some(TextCandidate {
        offset,
        encoding: encoding.to_string(),
        length: text.chars().count(),
        text,
    })
}

fn extract_text_fragments(bytes: &[u8], base_offset: usize) -> Vec<TextCandidate> {
    let mut fragments = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if !is_ascii_text_byte(bytes[offset]) {
            offset += 1;
            continue;
        }
        let start = offset;
        while offset < bytes.len() && is_ascii_text_byte(bytes[offset]) {
            offset += 1;
        }
        if offset - start >= 4 {
            let text = String::from_utf8_lossy(&bytes[start..offset]);
            if let Some(candidate) = make_text_candidate(base_offset + start, "ascii", &text) {
                fragments.push(candidate);
            }
        }
    }
    let mut offset = 0;
    while offset + 1 < bytes.len() {
        if !is_utf16_text_unit(bytes, offset)
            || (offset >= 2 && is_utf16_text_unit(bytes, offset - 2))
        {
            offset += 1;
            continue;
        }
        let start = offset;
        while is_utf16_text_unit(bytes, offset) {
            offset += 2;
        }
        if offset - start >= 8 {
            let units = bytes[start..offset]
                .chunks_exact(2)
                .map(|unit| u16::from_le_bytes(unit.try_into().unwrap()))
                .collect::<Vec<_>>();
            let text = String::from_utf16_lossy(&units);
            if let Some(candidate) = make_text_candidate(base_offset + start, "utf-16le", &text) {
                fragments.push(candidate);
            }
        }
    }
    fragments.sort_by_key(|fragment| fragment.offset);
    fragments.dedup_by_key(|fragment| fragment.offset);
    fragments
}

fn join_text_fragments(fragments: &[TextCandidate]) -> String {
    let mut output = String::new();
    let mut previous_offset = None;
    for fragment in fragments {
        if let Some(offset) = previous_offset {
            if fragment.offset.saturating_sub(offset) > 0x400 {
                output.push_str("\n\n");
            } else if !fragment
                .text
                .starts_with(|ch: char| ",.;:!?)]}".contains(ch))
            {
                output.push(' ');
            }
        }
        output.push_str(&fragment.text);
        previous_offset = Some(fragment.offset);
    }
    output
}

fn analyze_tart(bytes: &[u8], base_offset: usize) -> TartAnalysis {
    let mut type_11_count = 0;
    let mut type_12_count = 0;
    let mut offset = 0;
    while offset + 4 <= bytes.len() {
        let Some(run_type) = read_u16_le(bytes, offset) else {
            break;
        };
        if run_type == 0x11 {
            type_11_count += 1;
        } else if run_type == 0x12 {
            type_12_count += 1;
        }
        offset += 2;
    }
    let mut candidates = extract_text_fragments(bytes, base_offset);
    let text_fragment_count = candidates.len();
    let plain_text = join_text_fragments(&candidates);
    let text_length = plain_text.chars().count();
    candidates.truncate(64);
    TartAnalysis {
        type_11_count,
        type_12_count,
        candidates,
        text_fragment_count,
        text_length,
        plain_text,
    }
}

fn json_u32_summary(summary: &U32Summary) -> String {
    format!(
        "{{\"count\":{},\"min\":{},\"max\":{},\"monotonic\":{},\"permutation\":{},\"first\":[{}],\"last\":[{}]}}",
        summary.count,
        summary.min,
        summary.max,
        summary.monotonic,
        summary.permutation,
        summary.first.iter().map(|value| value.to_string()).collect::<Vec<_>>().join(","),
        summary.last.iter().map(|value| value.to_string()).collect::<Vec<_>>().join(","),
    )
}

fn json_tart(tart: &TartAnalysis) -> String {
    format!(
        "{{\"type_11_count\":{},\"type_12_count\":{},\"text_fragment_count\":{},\"text_length\":{},\"text_candidates\":[{}]}}",
        tart.type_11_count,
        tart.type_12_count,
        tart.text_fragment_count,
        tart.text_length,
        tart.candidates
            .iter()
            .map(|candidate| {
                format!(
                    "{{\"offset\":{},\"encoding\":{},\"length\":{},\"text\":{}}}",
                    candidate.offset,
                    json_string(&candidate.encoding),
                    candidate.length,
                    json_string(&preview(&candidate.text))
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub fn json(info: &LegacyInfo) -> String {
    format!(
        "{{\"path\":{},\"file_size\":{},\"magic\":\"LSFF\",\"kind\":{},\"declared_size\":{},\"blocks\":[{}],\"title_count\":{},\"titles\":[{}],\"plain_text_length\":{},\"ccct\":{},\"coff\":{},\"tart\":{},\"warnings\":[{}]}}",
        json_string(&info.path),
        info.file_size,
        json_string(&info.kind),
        info.declared_size,
        info.blocks
            .iter()
            .map(|block| {
                format!(
                    "{{\"descriptor_offset\":{},\"tag\":{},\"flags\":{},\"offset\":{},\"length\":{}}}",
                    block.descriptor_offset,
                    json_string(&block.tag),
                    block.flags,
                    block.offset,
                    block.length
                )
            })
            .collect::<Vec<_>>()
            .join(","),
        info.titles.len(),
        info.titles.iter().map(|title| json_string(title)).collect::<Vec<_>>().join(","),
        info.plain_text.chars().count(),
        info.ccct.as_ref().map(json_u32_summary).unwrap_or_else(|| "null".to_string()),
        info.coff.as_ref().map(json_u32_summary).unwrap_or_else(|| "null".to_string()),
        info.tart.as_ref().map(json_tart).unwrap_or_else(|| "null".to_string()),
        info.warnings.iter().map(|warning| json_string(warning)).collect::<Vec<_>>().join(","),
    )
}

pub fn human(info: &LegacyInfo) {
    println!("path                         {}", info.path);
    println!("file_size                    {}", info.file_size);
    println!("magic                        LSFF");
    println!("kind                         {}", info.kind);
    println!("declared_size                {}", info.declared_size + 8);
    println!("directory_blocks             {}", info.blocks.len());
    for block in &info.blocks {
        println!(
            "  {:<8} descriptor 0x{:X}, data 0x{:X}, {} bytes",
            block.tag, block.descriptor_offset, block.offset, block.length
        );
    }
    if !info.titles.is_empty() {
        println!("title_count                  {}", info.titles.len());
        for title in info.titles.iter().take(8) {
            println!("  title                      {title}");
        }
        if info.titles.len() > 8 {
            println!("  title                      ...");
        }
    }
    println!(
        "plain_text_length            {}",
        info.plain_text.chars().count()
    );
    if let Some(summary) = &info.ccct {
        println!(
            "ccct                         {} values, range {}..{}, monotonic {}",
            summary.count, summary.min, summary.max, summary.monotonic
        );
    }
    if let Some(summary) = &info.coff {
        println!(
            "coff                         {} values, range {}..{}, permutation {}",
            summary.count, summary.min, summary.max, summary.permutation
        );
    }
    if let Some(tart) = &info.tart {
        println!(
            "tart_runs                    type 0x11: {}, type 0x12: {}, text fragments: {}, text length: {}",
            tart.type_11_count,
            tart.type_12_count,
            tart.text_fragment_count,
            tart.text_length
        );
        for candidate in tart.candidates.iter().take(8) {
            println!(
                "  text_candidate             0x{:X} {} {}",
                candidate.offset,
                candidate.encoding,
                preview(&candidate.text)
            );
        }
    }
    for warning in &info.warnings {
        println!("warning                      {warning}");
    }
}

pub fn export(info: &LegacyInfo, root: &Path, stem: &str) -> Result<(), String> {
    fs::create_dir_all(root).map_err(|error| format!("create {}: {error}", root.display()))?;
    fs::write(
        root.join(format!("{stem}.json")),
        format!("{}\n", json(info)),
    )
    .map_err(|error| format!("write legacy JSON: {error}"))?;
    if !info.plain_text.is_empty() {
        fs::write(root.join(format!("{stem}.txt")), &info.plain_text)
            .map_err(|error| format!("write legacy text: {error}"))?;
    }
    Ok(())
}
