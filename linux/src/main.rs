#![allow(clippy::multiple_crate_versions)]
//! # Mavi VPN - Linux CLI Client
//!
//! A full-featured VPN client for Linux that uses QUIC transport.

#[cfg(target_os = "linux")]
pub mod daemon;
#[cfg(target_os = "linux")]
pub mod ech_client;
#[cfg(target_os = "linux")]
pub mod network;
#[cfg(target_os = "linux")]
pub mod oauth;
#[cfg(target_os = "linux")]
pub mod tun;
#[cfg(target_os = "linux")]
pub mod vpn_core;

#[cfg(target_os = "linux")]
mod cli;

#[cfg(target_os = "linux")]
fn main() {
    cli::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("The Mavi Linux VPN client can only be compiled for Linux.");
}
