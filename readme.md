# Codex sso flow

it uses codex sso flow to get access token, pls make use nothing is running at port 1455


## Example
```rust
use codex_sso_flow;

fn main() {
    codex_sso_flow::run_oauth_flow();
    println!("Hello, world!");
}
```
```bash
[dependencies]
codex_sso_flow = {git = "https://github.com/anshjoseph/codex_sso_flow"}
```

