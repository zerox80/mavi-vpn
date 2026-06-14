use crate::handle_service_control;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use windows_service::service::{
    ServiceControl, SessionChangeParam, SessionChangeReason, SessionNotification,
};
use windows_service::service_control_handler::ServiceControlHandlerResult;

fn session_change(reason: SessionChangeReason) -> ServiceControl {
    ServiceControl::SessionChange(SessionChangeParam {
        reason,
        notification: SessionNotification {
            size: std::mem::size_of::<SessionNotification>() as u32,
            session_id: 1,
        },
    })
}

#[test]
fn stop_control_sets_stop_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(ServiceControl::Stop, &stop, &reharden);
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(stop.load(Ordering::SeqCst));
    assert!(!reharden.load(Ordering::SeqCst));
    assert!(did_stop);
}

#[test]
fn shutdown_control_sets_stop_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(ServiceControl::Shutdown, &stop, &reharden);
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(stop.load(Ordering::SeqCst));
    assert!(did_stop);
}

#[test]
fn interrogate_returns_no_error() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(ServiceControl::Interrogate, &stop, &reharden);
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(!did_stop);
}

#[test]
fn unknown_control_returns_not_implemented() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(ServiceControl::Pause, &stop, &reharden);
    assert!(matches!(
        result,
        ServiceControlHandlerResult::NotImplemented
    ));
    assert!(!stop.load(Ordering::SeqCst));
    assert!(!did_stop);
}

#[test]
fn preshutdown_control_sets_stop_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(ServiceControl::Preshutdown, &stop, &reharden);
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(stop.load(Ordering::SeqCst));
    assert!(!reharden.load(Ordering::SeqCst));
    assert!(did_stop);
}

#[test]
fn session_logon_sets_reharden_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(
        session_change(SessionChangeReason::SessionLogon),
        &stop,
        &reharden,
    );
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(reharden.load(Ordering::SeqCst));
    assert!(!did_stop);
}

#[test]
fn console_connect_sets_reharden_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(
        session_change(SessionChangeReason::ConsoleConnect),
        &stop,
        &reharden,
    );
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(reharden.load(Ordering::SeqCst));
    assert!(!did_stop);
}

#[test]
fn remote_connect_sets_reharden_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(
        session_change(SessionChangeReason::RemoteConnect),
        &stop,
        &reharden,
    );
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(reharden.load(Ordering::SeqCst));
    assert!(!did_stop);
}

#[test]
fn session_unlock_sets_reharden_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(
        session_change(SessionChangeReason::SessionUnlock),
        &stop,
        &reharden,
    );
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(reharden.load(Ordering::SeqCst));
    assert!(!did_stop);
}

#[test]
fn session_logoff_does_not_set_reharden_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(
        session_change(SessionChangeReason::SessionLogoff),
        &stop,
        &reharden,
    );
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(!reharden.load(Ordering::SeqCst));
    assert!(!did_stop);
}

#[test]
fn session_lock_does_not_set_reharden_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(
        session_change(SessionChangeReason::SessionLock),
        &stop,
        &reharden,
    );
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(!reharden.load(Ordering::SeqCst));
    assert!(!did_stop);
}

#[test]
fn console_disconnect_does_not_set_reharden_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(
        session_change(SessionChangeReason::ConsoleDisconnect),
        &stop,
        &reharden,
    );
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(!reharden.load(Ordering::SeqCst));
    assert!(!did_stop);
}

#[test]
fn remote_disconnect_does_not_set_reharden_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (result, did_stop) = handle_service_control(
        session_change(SessionChangeReason::RemoteDisconnect),
        &stop,
        &reharden,
    );
    assert!(matches!(result, ServiceControlHandlerResult::NoError));
    assert!(!reharden.load(Ordering::SeqCst));
    assert!(!did_stop);
}

#[test]
fn session_change_never_sets_stop_signal() {
    let stop = Arc::new(AtomicBool::new(false));
    let reharden = Arc::new(AtomicBool::new(false));
    let (_, did_stop) = handle_service_control(
        session_change(SessionChangeReason::SessionLogon),
        &stop,
        &reharden,
    );
    assert!(!stop.load(Ordering::SeqCst));
    assert!(!did_stop);
}
