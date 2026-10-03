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
        }))
    }

    fn stopped(&self, id: Option<&str>) {
        if let Ok(mut state) = self.state.lock() {
            if id.is_none() || state.session_id.as_deref() == id {
                state.session_id = None;
            }
        }
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

    /// The service has accepted Start. Retain ownership even if cancellation
    /// won the race, until a Stop succeeds; its waiting caller may need to retry.
    pub(super) fn accept(&mut self) -> Result<(), String> {
        let mut state = self.lifecycle.state.lock().map_err(|e| e.to_string())?;
        let pending = state
            .pending
            .as_ref()
            .filter(|pending| pending.id == self.id)
            .ok_or("Connection attempt cancelled")?;
        let cancelled = *pending.cancel.borrow();
        state.pending = None;
        state.session_id = Some(self.id.clone());
        self.finished = true;
        if cancelled {
            return Err("Connection attempt cancelled".into());
        }
        Ok(())
    }

    pub(super) fn stopped(&self) {
        self.lifecycle.stopped(Some(&self.id));
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
}

impl StopOperation<'_> {
    /// Check after acquiring the operation lock: the pending Start may have
    /// been accepted, and its compensating Stop may have failed while we waited.
    pub(super) fn needs_service_stop(&self) -> Result<bool, String> {
        let state = self.lifecycle.state.lock().map_err(|e| e.to_string())?;
        Ok(self.id.is_none() || state.session_id == self.id)
    }

    pub(super) fn completed(&self) {
        self.lifecycle.stopped(self.id.as_deref());
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
