use openssl::symm::{Cipher, Crypter, Mode};
use openssl::ec::{EcKey, EcGroup};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::derive::Deriver;
use std::fs;
use std::time::Instant;

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
    // Load input text from file
    let input_text = fs::read_to_string("message.txt").expect("Failed to read message.txt");
    let data = input_text.trim_end().as_bytes();

    println!("\n================ ELLIPTIC CURVE ====================");
    println!("Plaintext: {}\n", input_text.trim_end());

    // Generate EC key pairs
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let alice_ec = EcKey::generate(&group).unwrap();
    let alice_pkey = PKey::from_ec_key(alice_ec).unwrap();
    let bob_ec = EcKey::generate(&group).unwrap();
    let bob_pkey = PKey::from_ec_key(bob_ec).unwrap();

    // Derive shared AES key from ECDH
    let mut deriver = Deriver::new(&alice_pkey).unwrap();
    deriver.set_peer(&bob_pkey).unwrap();
    let shared_secret = deriver.derive_to_vec().unwrap();
    let aes_key_from_ec = &shared_secret[..32];

    // Random IV
    let mut ec_iv = [0u8; 16];
    rand_bytes(&mut ec_iv).unwrap();

    // Encrypt and decrypt
    let start = Instant::now();
    let ec_encrypted = aes_encrypt(data, aes_key_from_ec, &ec_iv);
    let ec_decrypted = aes_decrypt(&ec_encrypted, aes_key_from_ec, &ec_iv);
    let ec_duration = start.elapsed().as_secs_f64();

    // Output
    println!("EC Shared Secret (used as AES key): {}\n", to_hex(aes_key_from_ec));
    println!("EC IV: {}\n", to_hex(&ec_iv));
    println!("EC AES Encrypted (hex): {}\n", to_hex(&ec_encrypted));
    println!("EC AES Decrypted: {}\n", String::from_utf8_lossy(&ec_decrypted));
    println!("EC Section Execution Time: {:.6} seconds", ec_duration);

    // Estimate: AES blocks + ECDH overhead
    let ec_blocks = (data.len() as f64 / 16.0).ceil();
    let ec_flops = 4000.0 * ec_blocks + 20000.0;
    let ec_mflops = ec_flops / (ec_duration * 1_000_000.0);
    println!("EC Approx. MFLOPS: {:.2}", ec_mflops);
}
