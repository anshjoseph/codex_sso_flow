// src/oauth.rs
use crate::config::Config;
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use urlencoding::encode;
use reqwest::blocking::Client;
use rand::RngCore;
use sha2::{Digest, Sha256};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD};



fn generate_pkce() -> (String, String) {
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



/// Builds the OAuth redirect URL and returns (code_verifier, url)
pub fn redirect_url_builder(auth_redirect_url: &str, config: &Config) -> (String, String) {
    let (code_verifier, code_challenge) = generate_pkce();

    let params = vec![
        ("response_type", "code"),
        ("client_id", &config.gpt_client_id),
        ("redirect_uri", auth_redirect_url),
        ("scope", &config.gpt_scope),
        ("code_challenge", &code_challenge),
        ("code_challenge_method", "S256"),
        ("state", &code_verifier),
        ("id_token_add_organizations", "true"),
        ("codex_cli_simplified_flow", "true"),
    ];

    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let url = format!("{}/oauth/authorize?{}", config.gpt_oauth_issuer, query);

    (code_verifier, url)
}


/// -----------------------------------------------------------
/// parse_jwt_claims
/// -----------------------------------------------------------
pub fn parse_jwt_claims(token: &str) -> Option<Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let payload = parts[1];

    // Add padding for proper base64 decoding
    let padded = format!(
        "{}{}",
        payload,
        "=".repeat((4 - payload.len() % 4) % 4)
    );

    let decoded = URL_SAFE.decode(padded.as_bytes()).ok()?;
    let json: Value = serde_json::from_slice(&decoded).ok()?;

    Some(json)
}

/// -----------------------------------------------------------
/// TokenData struct
/// -----------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenData {
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: String,
    pub account_id: String,
}

/// -----------------------------------------------------------
/// exchange_code_for_tokens (async)
/// -----------------------------------------------------------
pub fn exchange_code_for_tokens(
    code: &str,
    code_verifier: &str,
    auth_redirect_url: &str,
    config: &Config,
) -> Option<TokenData> {
    let token_endpoint = format!("{}/oauth/token", config.gpt_oauth_issuer);

    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", auth_redirect_url),
        ("client_id", &config.gpt_client_id),
        ("code_verifier", code_verifier),
    ];

    let client = Client::new();

    let resp = client
        .post(token_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&form)
        .send()        // sync call
        .ok()?;        // network error → None

    if resp.status() != 200 {
        return None;
    }

    let payload: Value = resp.json().ok()?; // sync JSON decode

    let id_token = payload["id_token"].as_str()?.to_string();
    let access_token = payload["access_token"].as_str()?.to_string();
    let refresh_token = payload["refresh_token"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Parse JWT for account_id
    let claims = parse_jwt_claims(&id_token)?;
    let account_id = claims["https://api.openai.com/auth"]["chatgpt_account_id"]
        .as_str()
        .unwrap_or("")
        .to_string();

    Some(TokenData {
        id_token,
        access_token,
        refresh_token,
        account_id,
    })
}
// pub async fn exchange_code_for_tokens(
//     code: &str,
//     code_verifier: &str,
//     auth_redirect_url: &str,
//     config: &Config,
// ) -> Option<TokenData> {
//     let token_endpoint = format!("{}/oauth/token", config.gpt_oauth_issuer);

//     let form = [
//         ("grant_type", "authorization_code"),
//         ("code", code),
//         ("redirect_uri", auth_redirect_url),
//         ("client_id", &config.gpt_client_id),
//         ("code_verifier", code_verifier),
//     ];

//     let client = reqwest::Client::new();

//     let resp = client
//         .post(token_endpoint)
//         .header("Content-Type", "application/x-www-form-urlencoded")
//         .form(&form)
//         .send()
//         .await
//         .ok()?; // network error → None

//     if resp.status() != 200 {
//         return None;
//     }

//     let payload: Value = resp.json().await.ok()?;

//     let id_token = payload["id_token"].as_str()?.to_string();
//     let access_token = payload["access_token"].as_str()?.to_string();
//     let refresh_token = payload["refresh_token"]
//         .as_str()
//         .unwrap_or("")
//         .to_string();

//     // Parse JWT for account_id
//     let claims = parse_jwt_claims(&id_token)?;
//     let account_id = claims["https://api.openai.com/auth"]["chatgpt_account_id"]
//         .as_str()
//         .unwrap_or("")
//         .to_string();

//     Some(TokenData {
//         id_token,
//         access_token,
//         refresh_token,
//         account_id,
//     })
// }
