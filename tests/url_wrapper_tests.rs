use peanut_task::chain::url_wrapper::{SafeUrl, SafeUrlError};

#[test]
fn test_redaction_with_api_key() {
    let safe_url = SafeUrl::new("https://api.example.com/v1?key={}", "secret123").unwrap();
    let redacted = safe_url.redacted();
    assert_eq!(redacted, "https://api.example.com/v1?key=****");
    assert!(!redacted.contains("secret123"));
}

#[test]
fn test_display_redacts() {
    let safe_url = SafeUrl::new("https://api.example.com/v1?key={}", "secret").unwrap();
    let display = format!("{}", safe_url);
    assert_eq!(display, "https://api.example.com/v1?key=****");
    assert!(!display.contains("secret"));
}

#[test]
fn test_debug_redacts() {
    let safe_url = SafeUrl::new("https://api.example.com/v1?key={}", "secret").unwrap();
    let debug = format!("{:?}", safe_url);
    assert!(!debug.contains("secret"));
    assert!(debug.contains("SafeUrl"));
    assert!(debug.contains("****"));
}

#[test]
fn test_as_url_returns_full() {
    let safe_url = SafeUrl::new("https://api.example.com/v1?key={}", "secret123").unwrap();
    let url = safe_url.as_url().unwrap();
    assert_eq!(url.as_str(), "https://api.example.com/v1?key=secret123");
}

#[test]
fn test_multiple_placeholders_error() {
    let result = SafeUrl::new("https://api.example.com/v1?key={}&other={}", "secret");
    assert!(matches!(result, Err(SafeUrlError::InvalidPlaceholderCount(2))));
}

#[test]
fn test_no_placeholder_error() {
    let result = SafeUrl::new("https://api.example.com/v1?key=value", "secret");
    assert!(matches!(result, Err(SafeUrlError::InvalidPlaceholderCount(0))));
}

#[test]
fn test_invalid_url_error() {
    let result = SafeUrl::new("not a url {}", "secret");
    assert!(matches!(result, Err(SafeUrlError::InvalidUrl(_))));
}

#[test]
fn test_different_placeholder_positions() {
    // Key at the end
    let safe_url = SafeUrl::new("https://api.example.com/v1?key={}", "secret").unwrap();
    assert_eq!(safe_url.redacted(), "https://api.example.com/v1?key=****");
    
    // Key in the middle
    let safe_url = SafeUrl::new("https://api.example.com/v1?key={}&other=value", "secret").unwrap();
    assert_eq!(safe_url.redacted(), "https://api.example.com/v1?key=****&other=value");
}
