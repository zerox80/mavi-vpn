use super::*;

#[test]
fn auth_message_allows_empty_tokens_in_wire_format() {
    let decoded: ControlMessage = roundtrip(&ControlMessage::Auth {
        token: String::new(),
    });

    match decoded {
        ControlMessage::Auth { token } => assert!(token.is_empty()),
        other => panic!("expected auth message, got {other:?}"),
    }
}
