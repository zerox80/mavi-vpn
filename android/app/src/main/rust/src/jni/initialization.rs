//! Cancellation is allocated before the worker starts, so Stop also reaches a
//! handshake that has not produced a native session handle yet.

use jni::objects::JClass;
use jni::sys::jlong;
use jni::EnvUnowned;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::watch;

fn pending() -> &'static Mutex<HashMap<jlong, watch::Sender<bool>>> {
    static PENDING: OnceLock<Mutex<HashMap<jlong, watch::Sender<bool>>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_nativelib_NativeLib_prepareInit(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jlong {
    prepare()
}

fn prepare() -> jlong {
    static NEXT_ID: AtomicI64 = AtomicI64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    pending()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(id, watch::channel(false).0);
    id
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_nativelib_NativeLib_cancelInit(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) {
    cancel(id);
}

fn cancel(id: jlong) {
    if let Some(sender) = pending()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&id)
    {
        sender.send_replace(true);
    }
}

pub(super) async fn run<T>(
    id: jlong,
    handshake: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let receiver = pending()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&id)
        .map(watch::Sender::subscribe)
        .ok_or_else(|| anyhow::anyhow!("Connection attempt cancelled"))?;
    run_cancellable(receiver, Duration::from_secs(20), handshake).await
}

async fn run_cancellable<T>(
    mut cancelled: watch::Receiver<bool>,
    timeout: Duration,
    handshake: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::select! {
        biased;
        () = async {
            while !*cancelled.borrow_and_update() {
                if cancelled.changed().await.is_err() { break; }
            }
        } => Err(anyhow::anyhow!("Connection attempt cancelled")),
        result = tokio::time::timeout(timeout, handshake) => {
            result.map_err(|_| anyhow::anyhow!("Connection attempt timed out"))?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stopping_an_old_worker_does_not_cancel_its_replacement() {
        let old = prepare();
        let current = prepare();
        cancel(old);
        assert!(run(old, std::future::pending::<anyhow::Result<()>>())
            .await
            .is_err());
        // The same worker can use its cancellation ID for multiple reconnects.
        for _ in 0..2 {
            assert_eq!(run(current, async { Ok(42) }).await.unwrap(), 42);
        }
        cancel(current);
        assert!(run(current, std::future::pending::<anyhow::Result<()>>())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn blackholed_initialization_times_out() {
        let (_sender, receiver) = watch::channel(false);
        let result = run_cancellable(
            receiver,
            Duration::from_millis(20),
            std::future::pending::<anyhow::Result<()>>(),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn stop_cancels_initialization_before_and_during_handshake() {
        for already_stopped in [true, false] {
            let (sender, receiver) = watch::channel(already_stopped);
            let task = tokio::spawn(run_cancellable(
                receiver,
                Duration::from_secs(60),
                std::future::pending::<anyhow::Result<()>>(),
            ));
            tokio::task::yield_now().await;
            sender.send_replace(true);
            let result = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            assert!(result.unwrap_err().to_string().contains("cancelled"));
        }
    }
}
