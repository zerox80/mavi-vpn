//! Serialize service mutations and cancel only the matching GUI request.
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Mutex;
use tokio::sync::{watch, Mutex as AsyncMutex};

#[derive(Default)]
pub(crate) struct ConnectionLifecycle {
    pub(super) operation: AsyncMutex<()>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    pending: Option<Pending>,
    session_id: Option<String>,
    stops: usize,
    // Also handle a cancel command dispatched before its connect command.
    cancelled: VecDeque<String>,
}

struct Pending {
    id: String,
    cancel: watch::Sender<bool>,
}

impl ConnectionLifecycle {
    pub(super) fn begin(&self, id: String) -> Result<ConnectAttempt<'_>, String> {
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        if let Some(index) = state
            .cancelled
            .iter()
            .position(|cancelled| cancelled == &id)
        {
            state.cancelled.remove(index);
            return Err("Connection attempt cancelled".into());
        }
        if state.pending.is_some() || state.stops > 0 {
            return Err("Another connection operation is still in progress".into());
        }
        let (cancel, receiver) = watch::channel(false);
        state.pending = Some(Pending {
            id: id.clone(),
            cancel,
        });
        Ok(ConnectAttempt {
            lifecycle: self,
            id,
            receiver,
            finished: false,
        })
    }

    pub(super) fn stop(&self, id: Option<&str>) -> Result<Option<StopOperation<'_>>, String> {
        let mut state = self.state.lock().map_err(|e| e.to_string())?;
        let pending_matches = state
            .pending
            .as_ref()
            .is_some_and(|pending| id.is_none_or(|id| pending.id == id));
        let session_matches = id.is_none() || state.session_id.as_deref() == id;
        if !pending_matches && !session_matches {
            if let Some(id) = id {
                state.cancelled.push_back(id.to_string());
                if state.cancelled.len() > 64 {
                    state.cancelled.pop_front();
                }
            }
            return Ok(None);
        }
        if pending_matches {
            state.pending.as_ref().unwrap().cancel.send_replace(true);
        }
        state.stops += 1;
        Ok(Some(StopOperation {
            lifecycle: self,
            id: id.map(String::from),
            needs_service_stop: session_matches,
        }))
    }
}

pub(super) struct ConnectAttempt<'a> {
    lifecycle: &'a ConnectionLifecycle,
    id: String,
    receiver: watch::Receiver<bool>,
    finished: bool,
}

impl ConnectAttempt<'_> {
    pub(super) async fn prepare<T>(
        &mut self,
        future: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        if *self.receiver.borrow() {
            return Err("Connection attempt cancelled".into());
        }
        tokio::select! {
            biased;
            _ = self.receiver.changed() => Err("Connection attempt cancelled".into()),
            result = future => result,
        }
    }

    /// Commit ownership under the same lock used by cancellation. A cancel
    /// either prevents acceptance or sees this ID as the active session.
    pub(super) fn accept(&mut self) -> Result<(), String> {
        let mut state = self.lifecycle.state.lock().map_err(|e| e.to_string())?;
        let pending = state
            .pending
            .as_ref()
            .filter(|pending| pending.id == self.id)
            .ok_or("Connection attempt cancelled")?;
        if *pending.cancel.borrow() {
            return Err("Connection attempt cancelled".into());
        }
        state.pending = None;
        state.session_id = Some(self.id.clone());
        self.finished = true;
        Ok(())
    }
}

impl Drop for ConnectAttempt<'_> {
    fn drop(&mut self) {
        if !self.finished {
            if let Ok(mut state) = self.lifecycle.state.lock() {
                if state
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.id == self.id)
                {
                    state.pending = None;
                }
            }
        }
    }
}

pub(super) struct StopOperation<'a> {
    lifecycle: &'a ConnectionLifecycle,
    id: Option<String>,
    pub(super) needs_service_stop: bool,
}

impl StopOperation<'_> {
    pub(super) fn completed(&self) {
        if let Ok(mut state) = self.lifecycle.state.lock() {
            if self.id.is_none() || state.session_id == self.id {
                state.session_id = None;
            }
        }
    }
}

impl Drop for StopOperation<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.lifecycle.state.lock() {
            state.stops -= 1;
        }
    }
}

#[cfg(test)]
mod tests;
