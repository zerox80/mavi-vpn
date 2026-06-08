use crate::handle_service_control;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use windows_service::service::ServiceControl;
use windows_service::service_control_handler::ServiceControlHandlerResult;

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
    assert!(matches!(result, ServiceControlHandlerResult::NotImplemented));
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
