use super::*;
use clap::Parser;

struct Subject(&'static str);
impl TokenValidator for Subject {
    fn validate_token<'a>(&'a self, _: &'a str) -> TokenValidationFuture<'a> {
        Box::pin(async {
            Ok(Some(ValidatedToken {
                sub: self.0.into(),
                exp: i64::MAX,
            }))
        })
    }
}

#[tokio::test]
async fn subject_quota_survives_token_rotation_and_source_changes() {
    let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
    let config = Config::parse_from(["vpn", "--max-sessions-per-principal", "2"]);
    let mut leases = Vec::new();
    for n in 1..=3 {
        let result = authenticate_client(
            &format!("token-{n}"),
            format!("192.0.2.{n}").parse().unwrap(),
            &state,
            &config,
            Some(&Subject("alice")),
        )
        .await;
        if n <= 2 {
            leases.push(result.unwrap());
        } else {
            assert!(result.is_err());
        }
    }
    let other = authenticate_client(
        "token",
        "192.0.2.1".parse().unwrap(),
        &state,
        &config,
        Some(&Subject("bob")),
    )
    .await
    .unwrap();
    state.release_ips(leases[0].0, leases[0].1);
    state.release_ips(leases[0].0, leases[0].1); // must not release another session's quota
    let next = authenticate_client(
        "rotated",
        "192.0.2.4".parse().unwrap(),
        &state,
        &config,
        Some(&Subject("alice")),
    )
    .await
    .unwrap();
    assert!(authenticate_client(
        "extra",
        "192.0.2.5".parse().unwrap(),
        &state,
        &config,
        Some(&Subject("alice"))
    )
    .await
    .is_err());
    for (ip4, ip6, _) in [leases.pop().unwrap(), other, next] {
        state.release_ips(ip4, ip6);
    }
}

#[tokio::test]
async fn shared_static_credential_has_one_quota_across_addresses() {
    let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
    let config = Config::parse_from([
        "vpn",
        "--auth-token",
        "secret",
        "--max-sessions-per-principal",
        "1",
    ]);
    let (a, b, _) = authenticate_client(
        "secret",
        "192.0.2.1".parse().unwrap(),
        &state,
        &config,
        None,
    )
    .await
    .unwrap();
    assert!(authenticate_client(
        "secret",
        "192.0.2.2".parse().unwrap(),
        &state,
        &config,
        None
    )
    .await
    .is_err());
    state.release_ips(a, b);
    assert!(authenticate_client(
        "secret",
        "192.0.2.2".parse().unwrap(),
        &state,
        &config,
        None
    )
    .await
    .is_ok());
}

#[test]
fn allocation_failure_does_not_leak_principal_reservation() {
    let state = AppState::new("10.8.0.0/30").unwrap();
    let (a, b) = state.assign_principal_ip_pair("alice".into(), 1).unwrap();
    assert!(state.assign_principal_ip_pair("bob".into(), 1).is_err());
    state.release_ips(a, b);
    assert!(state.assign_principal_ip_pair("bob".into(), 1).is_ok());
}

#[tokio::test]
async fn concurrent_authentication_cannot_race_quota() {
    let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
    let config = Arc::new(Config::parse_from([
        "vpn",
        "--max-sessions-per-principal",
        "2",
    ]));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let (state, config) = (state.clone(), config.clone());
        tasks.spawn(async move {
            authenticate_client(
                "token",
                "192.0.2.1".parse().unwrap(),
                &state,
                &config,
                Some(&Subject("alice")),
            )
            .await
        });
    }
    let mut accepted = 0;
    while let Some(result) = tasks.join_next().await {
        accepted += usize::from(result.unwrap().is_ok());
    }
    assert_eq!(accepted, 2);
}
