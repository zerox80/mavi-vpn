use super::*;
use crate::network::command::test_support::RecordingRunner;

const LEGACY: &str = r#"[
    {"dst":"::/1","type":"7","dev":"lo","protocol":"3","metric":1024},
    {"dst":"8000::/1","type":"7","dev":"lo","protocol":"3","metric":1024}
]"#;

#[test]
fn ordinary_cleanup_reports_legacy_blocks_without_removing_them() {
    let mut runner = RecordingRunner {
        outputs: [Ok(LEGACY.into())].into(),
        ..Default::default()
    };
    let diagnostic = check(&mut runner).unwrap_err().to_string();
    assert!(diagnostic.contains("sudo mavi-vpn repair --legacy-ipv6"));
    assert!(diagnostic.contains("manually configured routes"));
    assert_eq!(runner.calls.len(), 1);
    assert!(!runner.calls[0].1.iter().any(|arg| arg == "del"));
}

#[test]
fn explicit_repair_removes_only_the_exact_legacy_defaults() {
    let mut routes: Vec<serde_json::Value> = serde_json::from_str(LEGACY).unwrap();
    for (key, value) in [
        ("type", serde_json::json!("6")),
        ("dev", serde_json::json!("eth0")),
        ("protocol", serde_json::json!("99")),
        ("metric", serde_json::json!(1)),
        ("dst", serde_json::json!("::/2")),
    ] {
        let mut foreign = routes[0].clone();
        foreign[key] = value;
        routes.push(foreign);
    }
    let mut runner = RecordingRunner {
        outputs: [Ok("[]".into()), Ok(serde_json::to_string(&routes).unwrap())].into(),
        ..Default::default()
    };
    assert_eq!(repair(&mut runner).unwrap(), 2);
    assert_eq!(runner.calls.len(), 4);
    for (call, prefix) in runner.calls[2..].iter().zip(PREFIXES) {
        assert_eq!(
            call.1,
            [
                "-6",
                "route",
                "del",
                "unreachable",
                prefix,
                "table",
                "main",
                "dev",
                "lo",
                "proto",
                "3",
                "metric",
                "1024",
            ]
        );
    }
    // The same near-matches alone must not cause either deletion or a warning.
    runner.outputs = [
        Ok("[]".into()),
        Ok(serde_json::to_string(&routes[2..]).unwrap()),
        Ok(serde_json::to_string(&routes[2..]).unwrap()),
    ]
    .into();
    runner.calls.clear();
    assert_eq!(repair(&mut runner).unwrap(), 0);
    check(&mut runner).unwrap();
    assert_eq!(runner.calls.len(), 3);
}

#[test]
fn an_existing_tunnel_prevents_legacy_repair() {
    let mut runner = RecordingRunner {
        outputs: [Ok(r#"[{"ifname":"mavi0","operstate":"DOWN"}]"#.into())].into(),
        ..Default::default()
    };
    assert!(repair(&mut runner)
        .unwrap_err()
        .to_string()
        .contains("mavi0 still exists"));
    assert_eq!(runner.calls.len(), 1);
}

#[test]
fn inspection_and_deletion_failures_do_not_report_success() {
    for output in [Err(anyhow::anyhow!("ip failed")), Ok("invalid json".into())] {
        let mut runner = RecordingRunner {
            outputs: [output].into(),
            ..Default::default()
        };
        assert!(check(&mut runner).is_err());
        assert_eq!(runner.calls.len(), 1);
    }
    let mut runner = RecordingRunner {
        outputs: [Ok("[]".into()), Ok(LEGACY.into())].into(),
        outcomes: [Err(anyhow::anyhow!("permission denied"))].into(),
        ..Default::default()
    };
    let error = repair(&mut runner).unwrap_err();
    assert!(format!("{error:#}").contains("permission denied"));
}
