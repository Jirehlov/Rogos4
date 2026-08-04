use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::util::hex_upper;

pub fn sha1_bytes(bytes: &[u8]) -> String {
    let mut sha = Sha1::new();
    sha.update(bytes);
    hex_upper(&sha.finalize())
}

pub fn sha1_file_range(path: &Path, start: u64) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    file.seek(SeekFrom::Start(start))
        .map_err(|e| format!("seek {}: {e}", path.display()))?;
    let mut sha = Sha1::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let length = file
            .read(&mut buffer)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if length == 0 {
            break;
        }
        sha.update(&buffer[..length]);
    }
    Ok(hex_upper(&sha.finalize()))
}

pub fn salsa_block(
    key: &[u8],
    nonce: &[u8; 8],
    counter: u64,
    rounds: u32,
) -> Result<[u8; 64], String> {
    if key.len() != 16 && key.len() != 32 {
        return Err("Salsa20 key must be 16 or 32 bytes".to_string());
    }
    let mut key_words = [0u32; 8];
    for (index, word) in key_words.iter_mut().enumerate().take(key.len() / 4) {
        *word = u32::from_le_bytes(key[index * 4..index * 4 + 4].try_into().unwrap());
    }
    let constant = if key.len() == 16 {
        b"expand 16-byte k"
    } else {
        b"expand 32-byte k"
    };
    let c0 = u32::from_le_bytes(constant[0..4].try_into().unwrap());
    let c1 = u32::from_le_bytes(constant[4..8].try_into().unwrap());
    let c2 = u32::from_le_bytes(constant[8..12].try_into().unwrap());
    let c3 = u32::from_le_bytes(constant[12..16].try_into().unwrap());
    let iv0 = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    let iv1 = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    let mut state = if key.len() == 16 {
        [
            c0,
            key_words[0],
            key_words[1],
            key_words[2],
            key_words[3],
            c1,
            iv0,
            iv1,
            counter as u32,
            (counter >> 32) as u32,
            c2,
            key_words[0],
            key_words[1],
            key_words[2],
            key_words[3],
            c3,
        ]
    } else {
        [
            c0,
            key_words[0],
            key_words[1],
            key_words[2],
            key_words[3],
            c1,
            iv0,
            iv1,
            counter as u32,
            (counter >> 32) as u32,
            c2,
            key_words[4],
            key_words[5],
            key_words[6],
            key_words[7],
            c3,
        ]
    };
    let original = state;
    for _ in 0..(rounds / 2) {
        salsa_quarter_round(&mut state, 0, 4, 8, 12);
        salsa_quarter_round(&mut state, 5, 9, 13, 1);
        salsa_quarter_round(&mut state, 10, 14, 2, 6);
        salsa_quarter_round(&mut state, 15, 3, 7, 11);
        salsa_quarter_round(&mut state, 0, 1, 2, 3);
        salsa_quarter_round(&mut state, 5, 6, 7, 4);
        salsa_quarter_round(&mut state, 10, 11, 8, 9);
        salsa_quarter_round(&mut state, 15, 12, 13, 14);
    }
    let mut output = [0u8; 64];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4]
            .copy_from_slice(&word.wrapping_add(original[index]).to_le_bytes());
    }
    Ok(output)
}

pub fn xor_salsa_range(
    bytes: &mut [u8],
    start: usize,
    key: &[u8],
    nonce: &[u8; 8],
    rounds: u32,
) -> Result<(), String> {
    if start > bytes.len() {
        return Err("encrypted start is beyond EOF".to_string());
    }
    let mut position = start;
    while position < bytes.len() {
        let block_start = position - (position % 64);
        let keystream = salsa_block(key, nonce, (block_start / 64) as u64, rounds)?;
        let block_offset = position - block_start;
        let length = (64 - block_offset).min(bytes.len() - position);
        for index in 0..length {
            bytes[position + index] ^= keystream[block_offset + index];
        }
        position += length;
    }
    Ok(())
}

fn rotl(value: u32, amount: u32) -> u32 {
    value.rotate_left(amount)
}

fn salsa_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[b] ^= rotl(state[a].wrapping_add(state[d]), 7);
    state[c] ^= rotl(state[b].wrapping_add(state[a]), 9);
    state[d] ^= rotl(state[c].wrapping_add(state[b]), 13);
    state[a] ^= rotl(state[d].wrapping_add(state[c]), 18);
}

struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    message_len: u64,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buffer: [0; 64],
            buffer_len: 0,
            message_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.message_len = self.message_len.wrapping_add(data.len() as u64);
        let mut input = data;
        if self.buffer_len != 0 {
            let take = (64 - self.buffer_len).min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&input[..take]);
            self.buffer_len += take;
            input = &input[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }
        while input.len() >= 64 {
            self.process_block(input[..64].try_into().unwrap());
            input = &input[64..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_len = input.len();
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 80];
        for index in 0..16 {
            words[index] = u32::from_be_bytes(block[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (index, word) in words.iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }

    fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.message_len.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.process_block(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);
        let mut output = [0u8; 20];
        for (index, word) in self.state.iter().enumerate() {
            output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        output
    }
}
