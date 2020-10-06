mod aes;
mod constants;
mod utils;

use aes::{Base, KeyLength, KeyTextPair};
use std::{
    fs::File,
    io::{prelude::*, BufReader},
};

fn main() {
    let mut content = String::new();
    let file = File::open("input.txt").unwrap();
    for line in BufReader::new(file).lines() {
        content.push_str(line.unwrap().trim());
    }

    let input_data = KeyTextPair {
        cipher_key: Base::Hex("59454c4c4f57205355424d4152494e45".to_string()),
        cipher_text: Base::Base64(content),
        key_length: KeyLength::AES128,
    };

    let decrypted_bytes = aes::aes_decrypt(input_data);

    match aes::utf8_from_aes_grids(decrypted_bytes) {
        Ok(s) => println!("Decrypted bytes: {}", s),
        Err(e) => println!("Couldn't decrypt data. Error: {}", e),
    };
}
