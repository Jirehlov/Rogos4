use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::util::{hex_upper, parse_hex};

pub struct KeyEntry {
    pub key_hex: String,
    pub key: Vec<u8>,
}

pub struct KeyStore {
    path: PathBuf,
    license_master_key: Vec<u8>,
    keys: Vec<KeyEntry>,
    dirty: bool,
}

impl KeyStore {
    pub fn load(requested: Option<&Path>) -> Result<Self, String> {
        let path = resolve_path(requested)?;
        let text = fs::read_to_string(&path)
            .map_err(|error| format!("read key database {}: {error}", path.display()))?;
        let value = JsonParser::new(&text).parse()?;
        let object = value
            .as_object()
            .ok_or_else(|| "key database root must be a JSON object".to_string())?;
        let master_text = object
            .get("license_master_key")
            .and_then(JsonValue::as_string)
            .ok_or_else(|| "key database is missing license_master_key".to_string())?;
        let license_master_key = parse_hex(master_text)?;
        if license_master_key.len() != 32 {
            return Err("license_master_key must contain 32 bytes".to_string());
        }
        let key_values = object
            .get("keys")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| "key database is missing keys array".to_string())?;
        let mut keys = Vec::with_capacity(key_values.len());
        for (index, value) in key_values.iter().enumerate() {
            let key_text = value
                .as_string()
                .ok_or_else(|| format!("key entry {index} must be a hex string"))?;
            let key = parse_hex(key_text)?;
            if key.len() != 16 && key.len() != 32 {
                return Err(format!("key entry {index} must contain 16 or 32 bytes"));
            }
            let key_hex = hex_upper(&key);
            if keys.iter().any(|entry: &KeyEntry| entry.key_hex == key_hex) {
                continue;
            }
            keys.push(KeyEntry { key_hex, key });
        }
        Ok(Self {
            path,
            license_master_key,
            keys,
            dirty: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn license_master_key(&self) -> &[u8] {
        &self.license_master_key
    }

    pub fn keys(&self) -> &[KeyEntry] {
        &self.keys
    }

    pub fn add_key(&mut self, key: &[u8]) -> bool {
        let key_hex = hex_upper(key);
        if self.keys.iter().any(|entry| entry.key_hex == key_hex) {
            return false;
        }
        self.keys.push(KeyEntry {
            key_hex,
            key: key.to_vec(),
        });
        self.dirty = true;
        true
    }

    pub fn save_if_dirty(&mut self) -> Result<bool, String> {
        if !self.dirty {
            return Ok(false);
        }
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create key database directory {}: {error}",
                parent.display()
            )
        })?;
        let mut output = String::new();
        output.push_str("{\n  \"version\": 2,\n  \"license_master_key\": \"");
        output.push_str(&hex_upper(&self.license_master_key));
        output.push_str("\",\n  \"keys\": [\n");
        for (index, entry) in self.keys.iter().enumerate() {
            output.push_str("    \"");
            output.push_str(&entry.key_hex);
            output.push('"');
            if index + 1 != self.keys.len() {
                output.push(',');
            }
            output.push('\n');
        }
        output.push_str("  ]\n}\n");
        fs::write(&self.path, output)
            .map_err(|error| format!("write key database {}: {error}", self.path.display()))?;
        self.dirty = false;
        Ok(true)
    }
}

fn resolve_path(requested: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(path) = requested {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = env::var_os("ROGOS4_KEY_DB") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(executable) = env::current_exe() {
        if let Some(parent) = executable.parent() {
            let path = parent.join("keys.json");
            if path.is_file() {
                return Ok(path);
            }
        }
    }
    if let Ok(current) = env::current_dir() {
        let path = current.join("keys.json");
        if path.is_file() {
            return Ok(path);
        }
    }
    if let Some(app_data) = env::var_os("APPDATA") {
        return Ok(PathBuf::from(app_data).join("rogos4").join("keys.json"));
    }
    if let Some(config) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(config).join("rogos4").join("keys.json"));
    }
    env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".config/rogos4/keys.json"))
        .ok_or_else(|| "cannot determine default key database path; use --key-db PATH".to_string())
}

enum JsonValue {
    Null,
    Bool,
    Number,
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    fn as_object(&self) -> Option<ObjectView<'_>> {
        match self {
            Self::Object(value) => Some(ObjectView(value)),
            _ => None,
        }
    }
}

struct ObjectView<'a>(&'a [(String, JsonValue)]);

impl<'a> ObjectView<'a> {
    fn get(&self, name: &str) -> Option<&'a JsonValue> {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }
}

struct JsonParser<'a> {
    text: &'a [u8],
    position: usize,
}

impl<'a> JsonParser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text: text.as_bytes(),
            position: 0,
        }
    }

    fn parse(mut self) -> Result<JsonValue, String> {
        let value = self.parse_value()?;
        self.skip_whitespace();
        if self.position != self.text.len() {
            return Err(format!("unexpected JSON data at byte {}", self.position));
        }
        Ok(value)
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(JsonValue::String(self.parse_string()?)),
            Some(b't') => {
                self.expect_bytes(b"true")?;
                Ok(JsonValue::Bool)
            }
            Some(b'f') => {
                self.expect_bytes(b"false")?;
                Ok(JsonValue::Bool)
            }
            Some(b'n') => {
                self.expect_bytes(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(value) if value == b'-' || value.is_ascii_digit() => {
                self.parse_number();
                Ok(JsonValue::Number)
            }
            Some(_) => Err(format!("invalid JSON value at byte {}", self.position)),
            None => Err("unexpected end of JSON".to_string()),
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, String> {
        self.position += 1;
        let mut values = Vec::new();
        loop {
            self.skip_whitespace();
            if self.consume(b'}') {
                return Ok(JsonValue::Object(values));
            }
            let key = self.parse_string()?;
            self.skip_whitespace();
            if !self.consume(b':') {
                return Err(format!("expected ':' at byte {}", self.position));
            }
            let value = self.parse_value()?;
            values.push((key, value));
            self.skip_whitespace();
            if self.consume(b'}') {
                return Ok(JsonValue::Object(values));
            }
            if !self.consume(b',') {
                return Err(format!("expected ',' at byte {}", self.position));
            }
        }
    }

    fn parse_array(&mut self) -> Result<JsonValue, String> {
        self.position += 1;
        let mut values = Vec::new();
        loop {
            self.skip_whitespace();
            if self.consume(b']') {
                return Ok(JsonValue::Array(values));
            }
            values.push(self.parse_value()?);
            self.skip_whitespace();
            if self.consume(b']') {
                return Ok(JsonValue::Array(values));
            }
            if !self.consume(b',') {
                return Err(format!("expected ',' at byte {}", self.position));
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if !self.consume(b'"') {
            return Err(format!("expected string at byte {}", self.position));
        }
        let mut output = String::new();
        while let Some(value) = self.peek() {
            self.position += 1;
            match value {
                b'"' => return Ok(output),
                b'\\' => {
                    let escaped = self
                        .peek()
                        .ok_or_else(|| "unterminated JSON escape".to_string())?;
                    self.position += 1;
                    match escaped {
                        b'"' => output.push('"'),
                        b'\\' => output.push('\\'),
                        b'/' => output.push('/'),
                        b'b' => output.push('\u{0008}'),
                        b'f' => output.push('\u{000C}'),
                        b'n' => output.push('\n'),
                        b'r' => output.push('\r'),
                        b't' => output.push('\t'),
                        b'u' => {
                            let code = self.parse_unicode_escape()?;
                            let character = char::from_u32(code)
                                .ok_or_else(|| "invalid Unicode escape".to_string())?;
                            output.push(character);
                        }
                        _ => return Err(format!("invalid JSON escape at byte {}", self.position)),
                    }
                }
                value if value < 0x20 => return Err("control byte in JSON string".to_string()),
                value => output.push(value as char),
            }
        }
        Err("unterminated JSON string".to_string())
    }

    fn parse_unicode_escape(&mut self) -> Result<u32, String> {
        if self.position + 4 > self.text.len() {
            return Err("truncated Unicode escape".to_string());
        }
        let text = std::str::from_utf8(&self.text[self.position..self.position + 4])
            .map_err(|_| "invalid Unicode escape".to_string())?;
        self.position += 4;
        u32::from_str_radix(text, 16).map_err(|_| "invalid Unicode escape".to_string())
    }

    fn parse_number(&mut self) {
        while let Some(value) = self.peek() {
            if value.is_ascii_digit() || matches!(value, b'-' | b'+' | b'.' | b'e' | b'E') {
                self.position += 1;
            } else {
                break;
            }
        }
    }

    fn expect_bytes(&mut self, expected: &[u8]) -> Result<(), String> {
        if self.text.get(self.position..self.position + expected.len()) == Some(expected) {
            self.position += expected.len();
            Ok(())
        } else {
            Err(format!("unexpected JSON token at byte {}", self.position))
        }
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(|value| value.is_ascii_whitespace()) {
            self.position += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.position).copied()
    }
}
