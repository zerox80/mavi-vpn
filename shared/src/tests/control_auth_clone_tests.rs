use super::*;

#[test]
fn auth_message_clone_keeps_token() {
    let cloned = ControlMessage::Auth {
        token: "copy-me".to_string(),
    }
    .clone();

    match cloned {
        ControlMessage::Auth { token } => assert_eq!(token, "copy-me"),
        other => panic!("expected auth message, got {other:?}"),
    }
}
