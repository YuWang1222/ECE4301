use openssl::rsa::{Rsa, Padding};
use std::fs;
use std::time::Instant;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

fn main() {
    // Load input text from file
    let input_text = fs::read_to_string("message.txt").expect("Failed to read message.txt");
    let data = input_text.trim_end().as_bytes();

    println!("\n================ RSA ====================");
    println!("Plaintext: {}\n", input_text.trim_end());

    let rsa = Rsa::generate(2048).expect("Failed to generate RSA key");

    // Print keys
    let private_pem = rsa.private_key_to_pem().unwrap();
    let public_pem = rsa.public_key_to_pem().unwrap();
    println!("RSA Private Key (PEM):\n{}\n", String::from_utf8_lossy(&private_pem));
    println!("RSA Public Key (PEM):\n{}\n", String::from_utf8_lossy(&public_pem));

    // Encrypt & decrypt
    let mut rsa_encrypted = vec![0; rsa.size() as usize];
    let start = Instant::now();
    let enc_len = rsa.public_encrypt(data, &mut rsa_encrypted, Padding::PKCS1).unwrap();
    let mut rsa_decrypted = vec![0; enc_len];
    rsa.private_decrypt(&rsa_encrypted[..enc_len], &mut rsa_decrypted, Padding::PKCS1).unwrap();
    let rsa_duration = start.elapsed().as_secs_f64();

    println!("RSA Encrypted (hex): {}\n", to_hex(&rsa_encrypted[..enc_len]));
    println!("RSA Decrypted: {}\n", String::from_utf8_lossy(&rsa_decrypted));
    println!("RSA Execution Time: {:.6} seconds", rsa_duration);

    // Approximate flop count (depends on key size)
    let rsa_flops = 50_000.0;
    let rsa_mflops = rsa_flops / (rsa_duration * 1_000_000.0);
    println!("RSA Approx. MFLOPS: {:.2}", rsa_mflops);
}
