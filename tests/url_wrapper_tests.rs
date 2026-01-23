use peanut_task::chain::url_wrapper::{RpcUrl, RpcUrlError};

#[test]
fn test_redaction_with_api_key() {
    let rpc_url = RpcUrl::new("https://api.example.com/v1?key={}", "secret123").unwrap();
    let redacted = rpc_url.redacted();
    assert_eq!(redacted, "https://api.example.com/v1?key=****");
    assert!(!redacted.contains("secret123"));
}

#[test]
fn test_display_redacts() {
    let rpc_url = RpcUrl::new("https://api.example.com/v1?key={}", "secret").unwrap();
    let display = format!("{}", rpc_url);
    assert_eq!(display, "https://api.example.com/v1?key=****");
    assert!(!display.contains("secret"));
}

#[test]
fn test_debug_redacts() {
    let rpc_url = RpcUrl::new("https://api.example.com/v1?key={}", "secret").unwrap();
    let debug = format!("{:?}", rpc_url);
    assert!(!debug.contains("secret"));
    assert!(debug.contains("RpcUrl"));
    assert!(debug.contains("****"));
}

#[test]
fn test_as_url_returns_full() {
    let rpc_url = RpcUrl::new("https://api.example.com/v1?key={}", "secret123").unwrap();
    let url = rpc_url.as_url();
    assert_eq!(url.as_str(), "https://api.example.com/v1?key=secret123");
}

#[test]
fn test_multiple_placeholders_error() {
    let result = RpcUrl::new("https://api.example.com/v1?key={}&other={}", "secret");
    assert!(matches!(result, Err(RpcUrlError::InvalidPlaceholderCount(2))));
}

#[test]
fn test_no_placeholder_error() {
    let result = RpcUrl::new("https://api.example.com/v1?key=value", "secret");
    assert!(matches!(result, Err(RpcUrlError::InvalidPlaceholderCount(0))));
}

#[test]
fn test_invalid_url_error() {
    let result = RpcUrl::new("not a url {}", "secret");
    assert!(matches!(result, Err(RpcUrlError::InvalidUrl(_))));
}

#[test]
fn test_different_placeholder_positions() {
    // Key at the end
    let rpc_url = RpcUrl::new("https://api.example.com/v1?key={}", "secret").unwrap();
    assert_eq!(rpc_url.redacted(), "https://api.example.com/v1?key=****");
    
    // Key in the middle
    let rpc_url = RpcUrl::new("https://api.example.com/v1?key={}&other=value", "secret").unwrap();
    assert_eq!(rpc_url.redacted(), "https://api.example.com/v1?key=****&other=value");
}
