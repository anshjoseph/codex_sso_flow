# Codex sso flow

it uses codex sso flow to get access token, pls make use nothing is running at port 1455


## Example
```rust
use codex_sso_flow;

fn main() {
    let token_data: Option<TokenData> = codex_sso_flow::run_oauth_flow();
    println!("Hello, world!");
}
```
### Token Data
- id_token: String,
- access_token: String,
- refresh_token: String,
- account_id: String,



```bash
[dependencies]
codex_sso_flow = {git = "https://github.com/anshjoseph/codex_sso_flow"}
```

