use aes::Aes256;
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use block_padding::Pkcs7;
use rand::{RngCore, rngs::OsRng};
use std::fs;
use std::time::Instant;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

fn main() {
    let input_text = fs::read_to_string("message.txt").expect("Failed to read message.txt");
    let data = input_text.trim_end().as_bytes();

    println!("================ SOFTWARE-ONLY AES ====================");
    println!("Plaintext: {}\n", input_text.trim_end());

    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut iv);

    let cipher_enc = Aes256CbcEnc::new(&key.into(), &iv.into());
    let cipher_dec = Aes256CbcDec::new(&key.into(), &iv.into());

    let mut buffer = Vec::from(data);
    let pad_len = 16 - (data.len() % 16);
    buffer.resize(data.len() + pad_len, 0u8);

    let start = Instant::now();
    let ciphertext = cipher_enc
    .encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
    .unwrap()
    .to_vec();

    let duration = start.elapsed().as_secs_f64();

    let mut decrypted_buffer = ciphertext.clone();
    let decrypted_data = cipher_dec.decrypt_padded_mut::<Pkcs7>(&mut decrypted_buffer).unwrap();


    println!("AES Key: {}\n", to_hex(&key));
    println!("AES IV: {}\n", to_hex(&iv));
    println!("Encrypted (hex): {}\n", to_hex(&ciphertext));
    println!("Decrypted: {}\n", String::from_utf8_lossy(&decrypted_data));
    println!("Execution Time: {:.6} seconds", duration);

    let blocks = (data.len() as f64 / 16.0).ceil();
    let flops = 4000.0 * blocks;
    let mflops = flops / (duration * 1_000_000.0);
    println!("Approx. MFLOPS: {:.2}", mflops);
}
