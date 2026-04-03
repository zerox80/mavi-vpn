use super::*;

#[test]
fn error_message_clone_keeps_message() {
    let cloned = ControlMessage::Error {
        message: "copy-error".to_string(),
    }
    .clone();

    match cloned {
        ControlMessage::Error { message } => assert_eq!(message, "copy-error"),
        other => panic!("expected error message, got {other:?}"),
    }
}
