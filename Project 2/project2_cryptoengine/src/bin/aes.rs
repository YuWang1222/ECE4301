use openssl::symm::{Cipher, Crypter, Mode};
use openssl::rand::rand_bytes;
use std::fs;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

// AES encryption
fn aes_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
    let mut ciphertext = vec![0; data.len() + cipher.block_size()];
    let mut count = crypter.update(data, &mut ciphertext).unwrap();
    count += crypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);
    ciphertext
}

// AES decryption
fn aes_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).unwrap();
    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut count = crypter.update(ciphertext, &mut plaintext).unwrap();
    count += crypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);
    plaintext
}

fn main() {
    let input_text = fs::read_to_string("message.txt").expect("Failed to read message.txt");
    let data = input_text.trim_end().as_bytes();

    use std::time::Instant;

    println!("================ AES ====================");
    println!("Plaintext: {}\n", input_text.trim_end());

    let mut key = [0u8; 32]; // 256-bit key
    let mut iv = [0u8; 16];  // 128-bit IV
    rand_bytes(&mut key).unwrap();
    rand_bytes(&mut iv).unwrap();

    let start = Instant::now();
    let aes_encrypted = aes_encrypt(data, &key, &iv);
    let aes_decrypted = aes_decrypt(&aes_encrypted, &key, &iv);
    let aes_duration = start.elapsed().as_secs_f64();

    println!("AES Key (hex): {}\n", to_hex(&key));
    println!("AES IV  (hex): {}\n", to_hex(&iv));
    println!("AES Encrypted (hex): {}\n", to_hex(&aes_encrypted));
    println!("AES Decrypted: {}\n", String::from_utf8_lossy(&aes_decrypted));
    println!("AES Execution Time: {:.6} seconds", aes_duration);

    // Estimate: 4000 flops per 16-byte block
    let blocks = (data.len() as f64 / 16.0).ceil();
    let aes_flops = 4000.0 * blocks;
    let aes_mflops = aes_flops / (aes_duration * 1_000_000.0);
    println!("AES Approx. MFLOPS: {:.2}\n", aes_mflops);


}
