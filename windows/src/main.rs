#![allow(clippy::multiple_crate_versions)]
use anyhow::Result;

mod client_config;
mod client_ipc;
mod client_prompt;
mod ipc;
mod oauth;
mod secrets;

use client_ipc::send_request;
use client_prompt::{interactive_mode, load_or_prompt_config, read_line};
use ipc::IpcRequest;

#[tokio::main]
async fn main() {
    println!();
    println!("========================================");
    println!("         Mavi VPN - Windows");
    println!("========================================");
    println!();

    let args: Vec<String> = std::env::args().skip(1).collect();

    let result = if args.is_empty() {
        interactive_mode().await
    } else {
        dispatch_cli(&args).await
    };

    if let Err(e) = result {
        println!("\n[ERROR] Error: {e}");
    }

    println!("\nPress Enter to exit...");
    let _ = read_line();
}

async fn dispatch_cli(args: &[String]) -> Result<()> {
    let cmd = args[0].to_lowercase();
    match cmd.as_str() {
        "start" => {
            let config = load_or_prompt_config().await?;
            send_request(IpcRequest::Start(config)).await
        }
        "stop" => send_request(IpcRequest::Stop).await,
        "status" => send_request(IpcRequest::Status).await,
        "repair" => send_request(IpcRequest::RepairNetwork).await,
        _ => {
            println!("Unknown command: {cmd}");
            println!("Usage: mavi-vpn-client [start|stop|status|repair]");
            Ok(())
        }
    }
}

#[cfg(test)]
mod main_tests;
