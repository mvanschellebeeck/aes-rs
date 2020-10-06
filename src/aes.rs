use crate::constants;
use crate::utils::{self, BaseConversion};
use std::str;

type Grid = Vec<Vec<u8>>;
pub enum Base {
    Base64(String),
    Hex(String),
}

#[derive(Clone, Copy)]
pub enum KeyLength {
    AES128 = 128,
    AES192 = 192,
    AES256 = 256,
}

pub struct KeyTextPair {
    pub cipher_key: Base,
    pub cipher_text: Base,
    pub key_length: KeyLength,
}

pub trait AESGrid {
    fn xor_with(&mut self, other: &Grid);
    fn shift_rows_inv(&mut self);
    fn sub_bytes_inv(&mut self);
    fn mix_columns_inv(&mut self);
    fn set_column(&mut self, new_col: Vec<u8>, index: u8);
    fn get_column(&self, i: u8) -> Vec<u8>;
    fn to_hex(&self) -> Vec<String>;
    fn decrypt(&mut self, round_keys: &Vec<Grid>);
    fn polynomial(&self, a: u8, b: u8, c: u8, d: u8, col: usize) -> u8;
    fn transpose(&mut self) -> Self;
}

impl AESGrid for Grid {
    fn to_hex(&self) -> Vec<String> {
        let mut res = Vec::new();
        for column in 0..4 {
            res.push(self.get_column(column).to_hex_string());
        }
        res
    }

    fn get_column(&self, i: u8) -> Vec<u8> {
        self.iter().map(|v| v[i as usize]).collect()
    }

    fn set_column(&mut self, new_col: Vec<u8>, index: u8) {
        for row in 0..4 {
            self[row][index as usize] = new_col[row];
        }
    }

    fn xor_with(&mut self, other: &Grid) {
        for column in 0..4 {
            for row in 0..4 {
                self[row][column] = self[row][column] ^ other[row][column];
            }
        }
    }

    fn shift_rows_inv(&mut self) {
        self[1].rotate_right(1);
        self[2].rotate_right(2);
        self[3].rotate_left(1);
    }

    fn sub_bytes_inv(&mut self) {
        for column in 0..4 {
            for row in 0..4 {
                self[row][column] = inverse_sbox(self[row][column]);
            }
        }
    }

    // MixColumns Inverse using GF operations
    // https://en.wikipedia.org/wiki/Rijndael_MixColumns#InverseMixColumns
    //
    // b0 = (14 * d0) XOR (11 * d1) XOR (13 * d2) XOR ( 9 * d3)
    // b1 = ( 9 * d0) XOR (14 * d1) XOR (11 * d2) XOR (13 * d3)
    // b2 = (13 * d0) XOR ( 9 * d1) XOR (14 * d2) XOR (11 * d3)
    // b3 = (11 * d0) XOR (13 * d1) XOR ( 9 * d2) XOR (14 * d3)

    fn polynomial(&self, d0: u8, d1: u8, d2: u8, d3: u8, col: usize) -> u8 {
        // a + bx^3 + cx^2 + d ...
        gf_mult(d0, self[0][col])
            ^ gf_mult(d1, self[1][col])
            ^ gf_mult(d2, self[2][col])
            ^ gf_mult(d3, self[3][col])
    }

    fn mix_columns_inv(&mut self) {
        for column in 0..4 {
            self.set_column(
                vec![
                    self.polynomial(14, 11, 13, 9, column),
                    self.polynomial(9, 14, 11, 13, column),
                    self.polynomial(13, 9, 14, 11, column),
                    self.polynomial(11, 13, 9, 14, column),
                ],
                column as u8,
            );
        }
    }

    fn decrypt(&mut self, round_keys: &Vec<Grid>) {
        // iterate over round keys in reverse
        let last_round = round_keys.len() - 1;
        for (index, round_key) in round_keys.iter().rev().enumerate() {
            self.xor_with(round_key); // add round key
            if index != last_round {
                if index != 0 {
                    self.mix_columns_inv();
                }
                self.shift_rows_inv();
                self.sub_bytes_inv();
            }
        }
    }

    fn transpose(&mut self) -> Self {
        let mut vecs = vec![];
        for column in 0..self[0].len() {
            let mut column_vec = vec![];
            for row in 0..self.len() {
                column_vec.push(self[row][column]);
            }
            vecs.push(column_vec)
        }
        vecs
    }
}

// generalise this to accept unlimited args?
pub fn xor(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(i1, i2)| i1 ^ i2).collect()
}

pub fn to_cipher_key_grid(cipher_key: Vec<u8>, key_length: KeyLength) -> Grid {
    let mut aes_grid = match key_length {
        KeyLength::AES128 => Vec::with_capacity(4),
        KeyLength::AES192 => Vec::with_capacity(6),
        KeyLength::AES256 => Vec::with_capacity(8),
    };

    for byte in cipher_key.chunks(4) {
        aes_grid.push(byte.to_vec());
    }

    aes_grid
}

pub fn utf8_from_aes_grids(grids: Vec<Grid>) -> Result<String, str::Utf8Error> {
    let mut result: Vec<u8> = Vec::new();

    for grid in grids {
        for column in 0..4 {
            for row in 0..4 {
                result.push(grid[row][column]);
            }
        }
    }

    let s = str::from_utf8(&result)?;
    Ok(s.to_string())
}

pub fn to_aes_grids(cipher_key: Vec<u8>, key_length: KeyLength) -> Vec<Grid> {
    let mut res = Vec::new();

    let chunk_size = (key_length as usize) / 8;

    for a in cipher_key.chunks(chunk_size) {
        let mut aes_grid = vec![vec![0u8; 4]; 4];

        // transpose vals into AES grid
        for (index, &ch) in a.iter().enumerate() {
            aes_grid[index % 4][index / 4] = ch;
        }
        res.push(aes_grid);
    }
    res
}

pub fn generate_round_keys(grid: &mut Grid, key_length: KeyLength) -> Vec<Grid> {
    // N: length of the key in 32-bit words:
    // R: number of round keys required
    let (R, N): (usize, usize) = match key_length {
        KeyLength::AES128 => (11, 4),
        KeyLength::AES192 => (13, 6),
        KeyLength::AES256 => (15, 8),
    };

    let mut word_vec = Vec::with_capacity(4 * R - 1);
    word_vec.extend(grid.clone());

    for i in 0..4 * R {
        if i < N {
            continue;
        }

        let mut prev_word = word_vec[i - 1].clone();
        let nth_prev_word = word_vec[i - N].clone();

        if i >= N && i % N == 0 {
            // RotateWord
            prev_word.rotate_left(1);
            // SubBytes
            prev_word = prev_word.iter().map(|&b| sbox(b)).collect::<Vec<u8>>();

            word_vec.push(xor(
                xor(nth_prev_word, prev_word),
                vec![constants::RCON[i / N], 0, 0, 0],
            ));
        } else if i >= N && N > 6 && i % N == 4 {
            word_vec.push(xor(
                nth_prev_word,
                prev_word.iter().map(|&b| sbox(b)).collect::<Vec<u8>>(),
            ));
        } else {
            word_vec.push(xor(nth_prev_word, prev_word));
        }
    }

    // un-transpose
    word_vec
        .chunks(4)
        .map(|word| word.iter().cloned().collect::<Vec<_>>().transpose())
        .collect()
}

// multiplying in a Galois Field
// modulo(x^8 + x^4 + x^3 + x) --> 0x11B
pub fn gf_mult(x: u8, y: u8) -> u8 {
    let mut a = x as u32;
    let mut b = y as u32;
    let mut sum = 0u32;

    let modulus = 0x11B;
    let overflow = 0x100;

    while b > 0 {
        // handle 2^0
        if b & 0x1 == 1 {
            // add -> xor
            sum ^= a;
        }
        // discard last bit
        b >>= 1;
        // multiply a by 2
        a <<= 1;
        if a & overflow == overflow {
            a ^= modulus;
        }
    }
    sum as u8
}

pub fn inverse_sbox(byte: u8) -> u8 {
    let row = (byte & 0xF0) >> 4;
    let column = byte & 0x0F;
    constants::INV_SBOX[row as usize][column as usize]
}

pub fn sbox(byte: u8) -> u8 {
    let row = (byte & 0xF0) >> 4;
    let column = byte & 0x0F;
    constants::SBOX[row as usize][column as usize]
}

// main decryption function
pub fn aes_decrypt(encrypted_text: KeyTextPair) -> Vec<Grid> {
    let key_length = encrypted_text.key_length;

    let ct = match encrypted_text.cipher_text {
        Base::Base64(val) => to_aes_grids(utils::from_base64(&val), key_length),
        Base::Hex(val) => to_aes_grids(utils::from_hex(&val), key_length),
    };

    let mut ck = match encrypted_text.cipher_key {
        Base::Base64(val) => to_cipher_key_grid(utils::from_base64(&val), key_length),
        Base::Hex(val) => to_cipher_key_grid(utils::from_hex(&val), key_length),
    };

    let round_keys = generate_round_keys(&mut ck, key_length);
    let mut res = Vec::new();

    for grid in ct.iter() {
        let grid_clone = &mut grid.clone();
        grid_clone.decrypt(&round_keys);
        res.push(grid_clone.clone());
    }
    res
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_mix_columns_inv() {
        let mut grid = vec![
            vec![0x04, 0xE0, 0x48, 0x28],
            vec![0x66, 0xCB, 0xF8, 0x06],
            vec![0x81, 0x19, 0xD3, 0x26],
            vec![0xE5, 0x9A, 0x7A, 0x4C],
        ];

        grid.mix_columns_inv(); //actual

        let expected = vec![
            vec![0xD4, 0xE0, 0xB8, 0x1E],
            vec![0xBF, 0xB4, 0x41, 0x27],
            vec![0x5D, 0x52, 0x11, 0x98],
            vec![0x30, 0xAE, 0xF1, 0xE5],
        ];

        assert_eq!(expected, grid);
    }

    #[test]
    fn test_gf_mult() {
        assert_eq!(gf_mult(10, 20), 136);
    }

    #[test]
    fn test_shift_rows_inv() {
        let input = &mut vec![
            vec![0xD4, 0xE0, 0xB8, 0x1E],
            vec![0xBF, 0xB4, 0x41, 0x27],
            vec![0x5D, 0x52, 0x11, 0x98],
            vec![0x30, 0xAE, 0xF1, 0xE5],
        ];

        let expected = vec![
            vec![0xD4, 0xE0, 0xB8, 0x1E],
            vec![0x27, 0xBF, 0xB4, 0x41],
            vec![0x11, 0x98, 0x5D, 0x52],
            vec![0xAE, 0xF1, 0xE5, 0x30],
        ];

        input.shift_rows_inv(); // actual
        assert_eq!(expected, *input);
    }

    #[test]
    fn test_to_aes_grid() {
        let expected = vec![
            vec![0x59, 0x45, 0x4C, 0x4C],
            vec![0x4F, 0x57, 0x20, 0x53],
            vec![0x55, 0x4D, 0x42, 0x41],
            vec![0x52, 0x49, 0x4E, 0x45],
        ];

        let input = "YELLOW SUMBARINE".as_bytes().to_vec();
        let actual = to_cipher_key_grid(input, KeyLength::AES128);

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_generate_round_keys() {
        let input = "YELLOW SUMBARINE".as_bytes().to_vec();
        let mut grid = to_cipher_key_grid(input, KeyLength::AES128);

        let actual: Vec<String> = generate_round_keys(&mut grid, KeyLength::AES128)
            .iter()
            .flat_map(|rk| rk.to_hex())
            .collect();

        let expected = vec![
            "59454c4c", "4f572053", "554d4241", "52494e45", "636a224c", "2c3d021f", "7970405e",
            "2b390e1b", "73c18dbd", "5ffc8fa2", "268ccffc", "0db5c1e7", "a2b9196a", "fd4596c8",
            "dbc95934", "d67c98d3", "baff7f9c", "47bae954", "9c73b060", "4a0f28b3", "dccb124a",
            "9b71fb1e", "07024b7e", "4d0d63cd", "2b30afa9", "b04154b7", "b7431fc9", "fa4e7c04",
            "44205d84", "f4610933", "432216fa", "b96c6afe", "9422e6d2", "6043efe1", "2361f91b",
            "9a0d93e5", "58fe3f6a", "38bdd08b", "1bdc2990", "81d1ba75", "500aa266", "68b772ed",
            "736b5b7d", "f2bae108",
        ];

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_generate_round_keys_192() {
        let key_length = KeyLength::AES192;
        let input = "YELLOW SUMBARINE TEST AB".as_bytes().to_vec();
        let mut grid = to_cipher_key_grid(input, key_length);

        let actual: Vec<String> = generate_round_keys(&mut grid, key_length)
            .iter()
            .flat_map(|rk| rk.to_hex())
            .collect();

        let expected = vec![
            "59454c4c", "4f572053", "554d4241", "52494e45", "20544553", "54204142", "efc6606c",
            "a091403f", "f5dc027e", "a7954c3b", "87c10968", "d3e1482a", "1594850a", "b505c535",
            "40d9c74b", "e74c8b70", "608d8218", "b36cca32", "41e0a667", "f4e56352", "b43ca419",
            "53702f69", "33fdad71", "80916743", "c865bcaa", "3c80dff8", "88bc7be1", "dbcc5488",
            "e831f9f9", "68a09eba", "386e48ef", "04ee9717", "8c52ecf6", "579eb87e", "bfaf4187",
            "d70fdf3d", "6ef06fe1", "6a1ef8f6", "e64c1400", "b1d2ac7e", "0e7dedf9", "d97232c4",
            "6ed373d4", "04cd8b22", "e2819f22", "5353335c", "5d2edea5", "845cec61", "a41d9c8b",
            "a0d017a9", "4251888b", "1102bbd7",
        ];

        assert_eq!(expected, actual);
    }
    #[test]
    fn test_generate_round_keys_256() {
        let key_length = KeyLength::AES256;
        let input = "YELLOW SUBMARINE TEST AB12345678".as_bytes().to_vec();
        let mut grid = to_cipher_key_grid(input, key_length);

        let actual: Vec<String> = generate_round_keys(&mut grid, key_length)
            .iter()
            .flat_map(|rk| rk.to_hex())
            .collect();

        let expected = vec![
            "59454c4c", "4f572053", "55424d41", "52494e45", "20544553", "54204142", "31323334",
            "35363738", "5ddf4bda", "12886b89", "47ca26c8", "1583688d", "79b8000e", "2d98414c",
            "1caa7278", "299c4540", "81b1427f", "933929f6", "d4f30f3e", "c17067b3", "01e98563",
            "2c71c42f", "30dbb657", "1947f317", "25bcb2ab", "b6859b5d", "62769463", "a306f3d0",
            "0b868813", "27f74c3c", "172cfa6b", "0e6b097c", "52bda200", "e438395d", "864ead3e",
            "25485eee", "34d4d03b", "13239c07", "040f666c", "0a646f10", "01156867", "e52d513a",
            "6363fc04", "462ba2ea", "6e25eabc", "7d0676bb", "790910d7", "736d7fc7", "1dc7aee8",
            "f8eaffd2", "9b8903d6", "dda2a13c", "af1fd857", "d219aeec", "ab10be3b", "d87dc1fc",
            "a2bf1e89", "5a55e15b", "c1dce28d", "1c7e43b1",
        ];

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_aes_grids() {
        let cipher_text =
            utils::from_hex("459264f4798f6a78bacb89c15ed3d601459264f4798f6a78bacb89c15ed3d601");
        let actual = &mut to_aes_grids(cipher_text, KeyLength::AES128);

        let expected = vec![
            vec![
                vec![0x45, 0x79, 0xBA, 0x5E],
                vec![0x92, 0x8F, 0xCB, 0xD3],
                vec![0x64, 0x6A, 0x89, 0xD6],
                vec![0xF4, 0x78, 0xC1, 0x01],
            ],
            vec![
                vec![0x45, 0x79, 0xBA, 0x5E],
                vec![0x92, 0x8F, 0xCB, 0xD3],
                vec![0x64, 0x6A, 0x89, 0xD6],
                vec![0xF4, 0x78, 0xC1, 0x01],
            ],
        ];

        assert_eq!(expected, *actual);
    }

    #[test]
    fn test_aes_decrypt() {
        let test_data = KeyTextPair {
            cipher_key: Base::Hex("00000000000000000000000000000000".to_string()),
            cipher_text: Base::Hex("0336763E966D92595A567CC9CE537F5E".to_string()),
            key_length: KeyLength::AES128,
        };

        let actual = aes_decrypt(test_data);

        let expected = vec![vec![
            vec![0xF3, 0x3C, 0xCD, 0x08],
            vec![0x44, 0xC6, 0x5D, 0xF2],
            vec![0x81, 0x27, 0xC3, 0x73],
            vec![0xEC, 0xBA, 0xFB, 0xE6],
        ]];

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_aes_decrypt_2() {
        let test_data = KeyTextPair {
            cipher_key: Base::Hex("00000000000000000000000000000000".to_string()),
            cipher_text: Base::Hex("459264f4798f6a78bacb89c15ed3d601".to_string()),
            key_length: KeyLength::AES128,
        };

        let actual = aes_decrypt(test_data);

        let expected = vec![vec![
            vec![0xB2, 0x74, 0x35, 0x78],
            vec![0x6A, 0xE4, 0x8F, 0xF0],
            vec![0xEB, 0x7C, 0xF2, 0x91],
            vec![0x18, 0xA8, 0x23, 0x44],
        ]];

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_aes_decrypt_multigrid() {
        let test_data = KeyTextPair {
            cipher_key: Base::Hex("00000000000000000000000000000000".to_string()),
            cipher_text: Base::Hex(
                "0336763E966D92595A567CC9CE537F5E459264f4798f6a78bacb89c15ed3d601".to_string(),
            ),
            key_length: KeyLength::AES128,
        };

        let actual = aes_decrypt(test_data);

        let expected = vec![
            vec![
                vec![0xF3, 0x3C, 0xCD, 0x08],
                vec![0x44, 0xC6, 0x5D, 0xF2],
                vec![0x81, 0x27, 0xC3, 0x73],
                vec![0xEC, 0xBA, 0xFB, 0xE6],
            ],
            vec![
                vec![0xB2, 0x74, 0x35, 0x78],
                vec![0x6A, 0xE4, 0x8F, 0xF0],
                vec![0xEB, 0x7C, 0xF2, 0x91],
                vec![0x18, 0xA8, 0x23, 0x44],
            ],
        ];

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_aes_decrypt3() {
        let test_data = KeyTextPair {
            cipher_key: Base::Hex("2b7e151628aed2a6abf7158809cf4f3c".to_string()),
            cipher_text: Base::Hex("3925841d02dc09fbdc118597196a0b32".to_string()),
            key_length: KeyLength::AES128,
        };

        let actual = aes_decrypt(test_data);

        let expected = vec![vec![
            vec![0x32, 0x88, 0x31, 0xe0],
            vec![0x43, 0x5a, 0x31, 0x37],
            vec![0xf6, 0x30, 0x98, 0x07],
            vec![0xa8, 0x8d, 0xa2, 0x34],
        ]];

        assert_eq!(expected, actual);
    }
    #[test]
    fn test_aes_decrypt256() {
        let test_data = KeyTextPair {
            cipher_text: Base::Hex("8d853c88f9aec709b31b4bb3053a639f".to_string()),
            cipher_key: Base::Hex(
                "59454c4c4f57205355424d4152494e4520544553542041423132333435363738".to_string(),
            ),
            key_length: KeyLength::AES256,
        };

        let actual = aes_decrypt(test_data);

        let expected = vec![vec![
            vec![0x00, 0x44, 0x88, 0xCC],
            vec![0x11, 0x55, 0x99, 0xDD],
            vec![0x22, 0x66, 0xAA, 0xEE],
            vec![0x33, 0x77, 0xBB, 0xFF],
        ]];

        assert_eq!(expected, actual);
    }
}
