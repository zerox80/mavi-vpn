//! Unit tests for the JNI layer (init-error classification, etc.).

use super::*;

#[test]
fn classify_cert_pin_mismatch() {
    assert_eq!(
        classify_init_error("invalid certificate pin"),
        INIT_FATAL_CERT
    );
    assert_eq!(classify_init_error("pin mismatch"), INIT_FATAL_CERT);
    assert_eq!(
        classify_init_error("certificate pin mismatch"),
        INIT_FATAL_CERT
    );
}

#[test]
fn classify_auth_errors() {
    assert_eq!(
        classify_init_error("server error: Unauthorized"),
        INIT_FATAL_AUTH
    );
    assert_eq!(classify_init_error("Access Denied"), INIT_FATAL_AUTH);
    assert_eq!(
        classify_init_error("Invalid Keycloak Token"),
        INIT_FATAL_AUTH
    );
    assert_eq!(classify_init_error("Invalid Token"), INIT_FATAL_AUTH);
}

#[test]
fn classify_config_errors() {
    assert_eq!(
        classify_init_error("endpoint host missing"),
        INIT_FATAL_CONFIG
    );
    assert_eq!(classify_init_error("invalid address"), INIT_FATAL_CONFIG);
}

#[test]
fn classify_mtu_errors_as_permanent_config() {
    // A server/client MTU mismatch cannot be fixed by retrying.
    assert_eq!(
        classify_init_error(
            "MTU mismatch: local/client VPN MTU is 1280, but server pushed 1360"
        ),
        INIT_FATAL_CONFIG
    );
    assert_eq!(
        classify_init_error(
            "Server pushed unsupported VPN MTU 1500. Supported range is 1280-1360."
        ),
        INIT_FATAL_CONFIG
    );
}

#[test]
fn classify_unknown_returns_retryable() {
    assert_eq!(
        classify_init_error("connection timed out"),
        INIT_RETRYABLE_FAILURE
    );
    assert_eq!(
        classify_init_error("network unreachable"),
        INIT_RETRYABLE_FAILURE
    );
}

#[test]
fn classify_case_insensitive() {
    assert_eq!(
        classify_init_error("INVALID CERTIFICATE PIN"),
        INIT_FATAL_CERT
    );
    assert_eq!(classify_init_error("ACCESS DENIED"), INIT_FATAL_AUTH);
}

#[test]
fn retryable_failure_is_zero() {
    assert_eq!(INIT_RETRYABLE_FAILURE, 0);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn fatal_errors_are_negative() {
    assert!(INIT_FATAL_AUTH < 0);
    assert!(INIT_FATAL_CERT < 0);
    assert!(INIT_FATAL_CONFIG < 0);
}
