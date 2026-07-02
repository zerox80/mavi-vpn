use super::{try_acquire_ipc_slot, MAX_CONCURRENT_IPC_CLIENTS};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[test]
fn ipc_client_slots_are_bounded_and_released() {
    let slots = Arc::new(Semaphore::new(MAX_CONCURRENT_IPC_CLIENTS));
    let mut permits = Vec::new();

    for _ in 0..MAX_CONCURRENT_IPC_CLIENTS {
        permits.push(try_acquire_ipc_slot(&slots).expect("slot should be available"));
    }

    assert!(try_acquire_ipc_slot(&slots).is_none());
    drop(permits.pop());
    assert!(try_acquire_ipc_slot(&slots).is_some());
}
