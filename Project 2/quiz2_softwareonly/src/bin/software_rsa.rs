use rsa::{pkcs1v15::Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;
use std::fs;
use std::time::Instant;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

fn main() {
    let input_text = fs::read_to_string("message.txt").expect("Failed to read message.txt");
    let data = input_text.trim_end().as_bytes();

    println!("================ SOFTWARE-ONLY RSA ====================");
    println!("Plaintext: {}\n", input_text.trim_end());

    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
    let public_key = RsaPublicKey::from(&private_key);

    let start = Instant::now();
    let enc_data = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, data).unwrap();
    let dec_data = private_key.decrypt(Pkcs1v15Encrypt, &enc_data).unwrap();
    let duration = start.elapsed().as_secs_f64();

    println!("RSA Encrypted (hex): {}\n", to_hex(&enc_data));
    println!("RSA Decrypted: {}\n", String::from_utf8_lossy(&dec_data));
    println!("Execution Time: {:.6} seconds", duration);

    // Estimate (placeholder): RSA is not FLOP-heavy
    let rsa_flops = 50_000.0;
    let rsa_mflops = rsa_flops / (duration * 1_000_000.0);
    println!("Approx. MFLOPS: {:.2}", rsa_mflops);
}
