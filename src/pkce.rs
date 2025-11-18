// src/pkce.rs

use rand::RngCore;
use sha2::{Digest, Sha256};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

pub fn generate_pkce() -> (String, String) {
    // 64 random bytes
    let mut random_bytes = [0u8; 64];

    // NEW API: rand::rng() instead of thread_rng()
    rand::rng().fill_bytes(&mut random_bytes);

    // Convert to 128-character hex string
    let code_verifier = hex::encode(random_bytes);

    // SHA256 hash
    let digest = Sha256::digest(code_verifier.as_bytes());

    // Base64-url (no padding)
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);

    (code_verifier, code_challenge)
}
