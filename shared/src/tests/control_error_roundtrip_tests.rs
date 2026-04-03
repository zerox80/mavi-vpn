use super::*;

#[test]
fn error_message_roundtrips_through_bincode() {
    let decoded: ControlMessage = roundtrip(&ControlMessage::Error {
        message: "invalid token".to_string(),
    });

    match decoded {
        ControlMessage::Error { message } => assert_eq!(message, "invalid token"),
        other => panic!("expected error message, got {other:?}"),
    }
}
