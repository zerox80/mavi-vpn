use serde::{Deserialize, Serialize};

pub const LOCAL_IPC_ADDR: &str = "127.0.0.1:14433";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub token: String,
    pub cert_pin: String,
    pub censorship_resistant: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    Start(Config),
    Stop,
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    Ok,
    Error(String),
    Status { running: bool, endpoint: Option<String> },
}
