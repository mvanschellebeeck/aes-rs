use std::{char, str};
pub trait BaseConversion {
    fn to_base_64_string(&self) -> String;
    fn to_hex_string(&self) -> String;
}

impl BaseConversion for Vec<u8> {
    fn to_base_64_string(&self) -> String {
        self.chunks(3)
            .flat_map(|b| match b.len() {
                3 => vec![
                    b[0] >> 2,                         // take first 6 bits
                    ((b[0] & 0x3) << 4) + (b[1] >> 4), // take 2 bits of first byte and first 4 bits of next
                    ((b[1] & 0xF) << 2) + (b[2] >> 6), // take last 4 bits of first byte and first 2 of next byte
                    b[2] & 0x3F,                       // take last 6 bits
                ],
                2 => vec![b[0] >> 2, ((b[0] & 0x2) << 4) + (b[1] >> 4), (b[1] & 0xF)],
                1 => vec![b[0] >> 2, b[0] & 0x2],
                _ => panic!("This chunk has {} elements.", b.len()),
            })
            .map(|b| base64_to_char(&b))
            .collect()
    }

    fn to_hex_string(&self) -> String {
        self.iter()
            .flat_map(|b| vec![(b >> 4), (b & 0xF)])
            .map(|b| hex_to_char(b))
            .collect()
    }
}

pub fn base64_to_char(i: &u8) -> char {
    // Converts u8 to its base64 representation
    match i {
        0..=25 => (b'A' + i) as char,
        26..=51 => (b'a' + i - 26) as char,
        52..=61 => (b'0' + i - 52) as char,
        62 => '+',
        63 => '/',
        _ => '?',
    }
}

pub fn from_hex(s: &str) -> Vec<u8> {
    s.chars()
        .flat_map(|c| c.to_digit(16))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| ((c[0] << 4) + c[1]) as u8)
        .collect()
}

pub fn hex_to_char(i: u8) -> char {
    // hex u8 representation to A-F,0-9
    match i {
        0..=9 => (b'0' + i) as char,
        10..=15 => (b'a' + i - 10) as char,
        _ => panic!("{} is not a valid hex value", i),
    }
}


pub fn from_base64(s: &str) -> Vec<u8> {
    s.chars()
        .map(|b| u8_from_base64(b))
        .filter(|b| b.is_some())
        .map(|b| b.unwrap())
        .collect::<Vec<_>>()
        .chunks(4)
        .flat_map(|b| match b.len() {
            4 => vec![
                (b[0] << 2) + (b[1] >> 4),
                (b[1] << 4) + (b[2] >> 2),
                (b[2] << 6) + b[3],
            ],
            3 => vec![
                (b[0] << 2) + (b[1] >> 4),
                (b[1] << 4) + (b[2] >> 2),
                (b[2] << 6),
            ],
            _ => vec![],
        })
        .collect()
}

pub fn u8_from_base64(c: char) -> Option<u8> {
    match c {
        '=' => None, // padding
        'A'..='Z' => Some(c as u8 - b'A'),
        'a'..='z' => Some((c as u8 - b'a') + 26),
        '0'..='9' => Some((c as u8 - b'0') + 52),
        '+' => Some(62),
        '/' => Some(63),
        _ => panic!("Invalid base64 character [{}]", c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn base64_to_u8() {
        assert_eq!(from_base64("test"), vec![181, 235, 45]);
    }

    #[test]
    fn base64_with_padding_to_u8() {
        assert_eq!(from_base64("test===="), vec![181, 235, 45]);
    }

    #[test]
    fn test_to_hex_string() {
        assert_eq!(
            "YELLOW SUMBARINE".as_bytes().to_vec().to_hex_string(),
            "59454c4c4f572053554d424152494e45"
        );
    }
}
