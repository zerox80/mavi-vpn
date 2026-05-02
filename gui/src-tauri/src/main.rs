#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(clippy::multiple_crate_versions)]

fn main() {
    mavi_vpn_gui_lib::run();
}
