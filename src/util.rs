pub fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset.checked_add(2)?)
        .map(|value| u16::from_le_bytes(value.try_into().unwrap()))
}

pub fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|value| u32::from_le_bytes(value.try_into().unwrap()))
}

pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return Err("hex value must have a non-zero even length".to_string());
    }
    let mut output = Vec::with_capacity(text.len() / 2);
    for index in (0..text.len()).step_by(2) {
        let high = text.as_bytes()[index] as char;
        let low = text.as_bytes()[index + 1] as char;
        let high = high
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex at byte {index}"))?;
        let low = low
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex at byte {}", index + 1))?;
        output.push(((high << 4) | low) as u8);
    }
    Ok(output)
}

pub fn hex_upper(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0F) as usize] as char);
    }
    output
}

pub fn json_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch.is_control() => output.push_str(&format!("\\u{:04X}", ch as u32)),
            ch => output.push(ch),
        }
    }
    output
}

pub fn json_string(value: &str) -> String {
    format!("\"{}\"", json_escape(value))
}
