use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use shared::ControlMessage;
use tokio::sync::broadcast;

pub struct VpnSession {
    pub runtime: tokio::runtime::Runtime,
    pub connection: quinn::Connection,
    pub config: ControlMessage,
    pub stop_flag: Arc<AtomicBool>,
    pub shutdown_tx: broadcast::Sender<()>,
}

impl VpnSession {
    pub fn new(
        runtime: tokio::runtime::Runtime,
        connection: quinn::Connection,
        config: ControlMessage,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            runtime,
            connection,
            config,
            stop_flag: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }
}
