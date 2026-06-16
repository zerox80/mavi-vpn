#![allow(unsafe_code)]

use anyhow::Context;
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        SessionChangeReason,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[path = "../../ech_client.rs"]
mod ech_client;
#[path = "../../ipc.rs"]
mod ipc;
#[path = "../../vpn_core/mod.rs"]
mod vpn_core;

mod cli;
mod handlers;
mod main_loop;
mod state;
mod utils;

#[cfg(test)]
mod tests;

use crate::cli::SERVICE_NAME;

const SERVICE_TYPE: windows_service::service::ServiceType =
    windows_service::service::ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, my_service_main);

pub fn main() -> Result<(), windows_service::Error> {
    let mut env_filter = tracing_subscriber::EnvFilter::from_default_env();
    for directive in ["mavi_vpn=info", "wintun=off"] {
        match directive.parse() {
            Ok(parsed) => env_filter = env_filter.add_directive(parsed),
            Err(e) => warn!("Ignoring invalid tracing directive {directive:?}: {e}"),
        }
    }
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    info!("Starting service dispatcher for {}", SERVICE_NAME);
    let args: Vec<OsString> = std::env::args_os().collect();

    if args.iter().any(|arg| arg == "--console") {
        info!("Running in console mode");
        if let Err(e) = cli::run_standalone() {
            error!("Console service run failed: {e:#}");
        }
        return Ok(());
    }

    if args.iter().any(|arg| arg == "install") {
        cli::install_service();
        return Ok(());
    }

    if args.iter().any(|arg| arg == "uninstall") {
        cli::uninstall_service();
        return Ok(());
    }

    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn my_service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        error!("Service run failed: {:?}", e);
    }
}

pub(crate) fn handle_service_control(
    control_event: ServiceControl,
    stop_signal: &Arc<AtomicBool>,
    reharden_signal: &Arc<AtomicBool>,
) -> (ServiceControlHandlerResult, bool) {
    let mut did_stop = false;
    let result = match control_event {
        event @ (ServiceControl::Stop | ServiceControl::Preshutdown | ServiceControl::Shutdown) => {
            info!("Received {:?} signal from Service Control Manager", event);
            stop_signal.store(true, Ordering::SeqCst);
            did_stop = true;
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::SessionChange(param) => {
            if matches!(
                param.reason,
                SessionChangeReason::SessionLogon
                    | SessionChangeReason::ConsoleConnect
                    | SessionChangeReason::RemoteConnect
                    | SessionChangeReason::SessionUnlock
            ) {
                info!(
                    "Session change ({:?}) for session {} - queuing IPC token ACL re-harden",
                    param.reason, param.notification.session_id
                );
                reharden_signal.store(true, Ordering::SeqCst);
            }
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    (result, did_stop)
}

fn run_service(_arguments: Vec<OsString>) -> anyhow::Result<()> {
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal_handler = stop_signal.clone();
    let reharden_signal = Arc::new(AtomicBool::new(false));
    let reharden_signal_handler = reharden_signal.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        let (result, did_stop) = handle_service_control(
            control_event,
            &stop_signal_handler,
            &reharden_signal_handler,
        );
        if did_stop {
            utils::run_network_repair_cleanup();
        }
        result
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP
            | ServiceControlAccept::PRESHUTDOWN
            | ServiceControlAccept::SESSION_CHANGE,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create Tokio runtime")?;

    info!("Service is now running");

    let res = rt.block_on(main_loop::run_service_loop(stop_signal, reharden_signal));
    if let Err(e) = res {
        error!("Service loop failed: {}", e);
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}
