use super::*;

#[test]
fn auth_message_roundtrips_through_bincode() {
    let decoded: ControlMessage = roundtrip(&ControlMessage::Auth {
        token: "secret-token".to_string(),
    });

    match decoded {
        ControlMessage::Auth { token } => assert_eq!(token, "secret-token"),
        other => panic!("expected auth message, got {other:?}"),
    }
}
