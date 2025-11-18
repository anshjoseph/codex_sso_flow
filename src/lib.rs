mod oauth;
mod config;

use crate::oauth::{redirect_url_builder, exchange_code_for_tokens};
use crate::config::Config;
use crate::oauth::TokenData;
use std::{
    net::TcpListener,
    io::{BufReader, BufRead, Write},
};
use webbrowser;


/// ---------------------------------------------
/// Run the full OAuth flow and return TokenData
/// ---------------------------------------------
pub fn run_oauth_flow() -> Option<TokenData> {
    let cfg = Config {
        gpt_oauth_issuer: "https://auth.openai.com".into(),
        gpt_client_id: "app_EMoamEEZ73f0CkXaXp7hrann".into(),
        gpt_scope: "openid profile email offline_access".into(),
    };
    let redirect_uri = "http://localhost:1455/auth/callback";

    // Build OAuth URL
    let (code_verifier, redirect_url) = redirect_url_builder(redirect_uri, &cfg);

    println!("\n[OAuth] Opening browser:\n{redirect_url}\n");

    // Open browser
    webbrowser::open(&redirect_url).ok()?;

    // Start HTTP callback server
    let listener = TcpListener::bind("127.0.0.1:1455").ok()?;
    println!("[OAuth] Waiting for authorization code...");

    for stream in listener.incoming() {
        let mut stream = stream.ok()?;
        let buf_reader = BufReader::new(&stream);

        let http_request: Vec<String> = buf_reader
            .lines()
            .map(|l| l.unwrap_or_default())
            .take_while(|line| !line.is_empty())
            .collect();

        let path_line = http_request.first()?.to_string();
        let code = extract_query_code(&path_line);

        println!("\n[OAuth] Received code:\n{code}\n");

        // Respond to browser
        let body = "<html><body><h1>Login Successful</h1>You can close this window.</body></html>";

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        stream.write_all(response.as_bytes()).ok()?;

        // Exchange code for tokens
        let token_data = exchange_code_for_tokens(
            &code,
            &code_verifier,
            redirect_uri,
            &cfg,
        );

        return token_data; // return tokens back to caller
    }

    None
}


/// Extract ?code=XXXX from request line
fn extract_query_code(request_line: &str) -> String {
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return "".into();
    }
    let url_path = parts[1];
    if let Some(start) = url_path.find('?') {
        let query = &url_path[start + 1..];
        for kv in query.split('&') {
            let mut pair = kv.split('=');
            if pair.next().unwrap_or("") == "code" {
                return pair.next().unwrap_or("").to_string();
            }
        }
    }
    "".into()
}
