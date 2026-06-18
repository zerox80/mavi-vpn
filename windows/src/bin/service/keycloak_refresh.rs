use shared::ipc::{KeycloakRuntimeAuth, KEYCLOAK_LOGIN_REQUIRED_PREFIX};
use shared::kc_oauth::{self, RefreshOutcome};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tracing::{info, warn};

use super::state::{PendingKeycloakRefreshToken, VpnRuntimeHandles};

const REFRESH_SKEW_SECS: u64 = 300;
const REFRESH_TICK: Duration = Duration::from_secs(30);

pub fn spawn_keycloak_refresh_task(
    keycloak: KeycloakRuntimeAuth,
    initial_access_token: String,
    runtime: VpnRuntimeHandles,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_keycloak_refresh_loop(keycloak, initial_access_token, runtime).await;
    })
}

async fn run_keycloak_refresh_loop(
    keycloak: KeycloakRuntimeAuth,
    mut access_token: String,
    runtime: VpnRuntimeHandles,
) {
    let mut refresh_token = keycloak.refresh_token;

    loop {
        if !runtime.running.load(Ordering::SeqCst) {
            break;
        }

        if !kc_oauth::is_access_token_usable(&access_token, REFRESH_SKEW_SECS) {
            match kc_oauth::refresh_access_token(
                &keycloak.kc_url,
                &keycloak.realm,
                &keycloak.client_id,
                &refresh_token,
            )
            .await
            {
                RefreshOutcome::Success(tokens) => {
                    access_token = tokens.access_token;
                    runtime.set_current_token(access_token.clone());

                    if let Some(rotated_refresh) = tokens.refresh_token {
                        if !rotated_refresh.is_empty() && rotated_refresh != refresh_token {
                            refresh_token = rotated_refresh.clone();
                            runtime.publish_keycloak_refresh_token(PendingKeycloakRefreshToken {
                                connection_id: keycloak.connection_id.clone(),
                                refresh_token: rotated_refresh,
                            });
                        }
                    }

                    info!("Keycloak access token refreshed in Windows service");
                }
                RefreshOutcome::NetworkError(message) => {
                    warn!("Keycloak refresh failed transiently: {message}");
                }
                RefreshOutcome::NeedsLogin(message) => {
                    warn!("Keycloak refresh requires interactive login: {message}");
                    if let Ok(mut last_error) = runtime.last_error.lock() {
                        *last_error = Some(format!("{KEYCLOAK_LOGIN_REQUIRED_PREFIX} {message}"));
                    }
                    runtime.running.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }

        tokio::time::sleep(REFRESH_TICK).await;
    }
}
