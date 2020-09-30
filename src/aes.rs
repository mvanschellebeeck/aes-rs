use std::str;
use crate::constants;
use crate::utils::{
    self,
    BaseConversion
};

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

    fn polynomial(&self, d0: u8, d1: u8, d2: u8, d3: u8, col: usize) -> u8{
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
        for (index, round_key) in round_keys.iter().rev().enumerate() {
            self.xor_with(round_key); // add round key
            if index != 10 {
                if index != 0 {
                    self.mix_columns_inv();
                }
                self.shift_rows_inv();
                self.sub_bytes_inv();
            }
        }
    }
}

// generalise this to accept unlimited args?
pub fn xor(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(i1, i2)| i1 ^ i2).collect()
}

pub fn to_cipher_key_grid(cipher_key: Vec<u8>, key_length: KeyLength) -> Grid {
    let (mut aes_grid, rows) = match key_length {
        KeyLength::AES128 => (vec![vec![0u8; 4]; 4], 4),
        KeyLength::AES192 => (vec![vec![0u8; 4]; 6], 6),
        KeyLength::AES256 => (vec![vec![0u8; 4]; 8], 8),
    };

    // transpose vals into AES grid
    for (index, &ch) in cipher_key.iter().enumerate() {
        aes_grid[index % rows][index / rows] = ch;
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

    let (rounds, mut current): (usize, Vec<u8>) = match key_length  {
        KeyLength::AES128 => (10, vec![0; 4]),
        KeyLength::AES192 => (12, vec![0; 6]),
        KeyLength::AES256 => (14, vec![0; 8]),
    };

    let mut round_keys = vec![grid.clone()];

    for round_no in 0..rounds {
        for column_index in 0..4 {
            current = if column_index == 0 {
                // RotWord
                let mut bytes_3 = grid.get_column(3);
                bytes_3.rotate_left(1);
                // SubBytes
                bytes_3 = bytes_3.iter().map(|&b| sbox(b)).collect::<Vec<u8>>();
                let bytes_0 = grid.get_column(0);
                xor(xor(bytes_0, bytes_3), constants::RCON[round_no].to_vec())
            } else {
                let bytes = grid.get_column(column_index);
                xor(bytes, current.clone())
            };

            grid.set_column(current.clone(), column_index);
        }
        round_keys.push(grid.clone());
    }
    round_keys
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
            vec![0x59, 0x4F, 0x55, 0x52],
            vec![0x45, 0x57, 0x4D, 0x49],
            vec![0x4C, 0x20, 0x42, 0x4E],
            vec![0x4C, 0x53, 0x41, 0x45],
        ];

        let input = "YELLOW SUMBARINE".as_bytes().to_vec();
        let actual = to_cipher_key_grid(input, KeyLength::AES128);

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_generate_round_keys() {
        let input = "YELLOW SUMBARINE".as_bytes().to_vec();
        let mut grid= to_cipher_key_grid(input, KeyLength::AES128);

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
    fn test_aes_grids() {
        let cipher_text = utils::from_hex(
            "459264f4798f6a78bacb89c15ed3d601459264f4798f6a78bacb89c15ed3d601",
        );
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
}

