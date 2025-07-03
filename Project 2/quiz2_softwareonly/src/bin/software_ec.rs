use aes::Aes256;
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use block_padding::Pkcs7;
use rand::{RngCore, rngs::OsRng};
use p256::{
    ecdh::EphemeralSecret,
    EncodedPoint,
    PublicKey,
};
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

    println!("================ SOFTWARE-ONLY EC ====================");
    println!("Plaintext: {}\n", input_text.trim_end());

    let alice_secret = EphemeralSecret::random(&mut OsRng);
    let alice_public = EncodedPoint::from(alice_secret.public_key());

    let bob_secret = EphemeralSecret::random(&mut OsRng);
    let bob_public = EncodedPoint::from(bob_secret.public_key());

    let bob_pubkey = PublicKey::from_sec1_bytes(bob_public.as_bytes()).unwrap();
    let shared_secret = alice_secret.diffie_hellman(&bob_pubkey);
    let aes_key = &shared_secret.raw_secret_bytes()[..32];

    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let cipher_enc = Aes256CbcEnc::new(aes_key.into(), &iv.into());
    let cipher_dec = Aes256CbcDec::new(aes_key.into(), &iv.into());

    let mut buffer = Vec::from(data);
    let pad_len = 16 - (data.len() % 16);
    buffer.resize(data.len() + pad_len, 0u8);

    let start = Instant::now();
    let encrypted = cipher_enc
    .encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
    .unwrap()
    .to_vec();
    let duration = start.elapsed().as_secs_f64();

    let mut decrypted_buffer = encrypted.clone();
    let decrypted = cipher_dec.decrypt_padded_mut::<Pkcs7>(&mut decrypted_buffer).unwrap();

    println!("EC-Derived AES Key: {}\n", to_hex(aes_key));
    println!("IV: {}\n", to_hex(&iv));
    println!("Encrypted (hex): {}\n", to_hex(&encrypted));
    println!("Decrypted: {}\n", String::from_utf8_lossy(&decrypted));
    println!("Execution Time: {:.6} seconds", duration);

    let blocks = (data.len() as f64 / 16.0).ceil();
    let flops = 4000.0 * blocks + 20000.0;
    let mflops = flops / (duration * 1_000_000.0);
    println!("Approx. MFLOPS: {:.2}", mflops);
}
