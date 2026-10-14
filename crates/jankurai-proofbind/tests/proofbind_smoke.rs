use std::fs;
use std::path::PathBuf;

use jankurai_proofbind::{build_proofbind, ProofBindMode, ProofBindRequest};
use tempfile::tempdir;

fn seed_repo() -> tempfile::TempDir {
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("agent")).unwrap();
    fs::create_dir_all(repo.path().join("src")).unwrap();
    fs::write(
        repo.path().join("agent/owner-map.json"),
        r#"{"workspace":"fixture","owners":{"src/":"tools","db/":"standard","agent/":"agent"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"src/":{"command":"cargo test -p fixture","purpose":"rust"},"db/":{"command":"cargo run -p jankurai -- migrate . --analyze --json target/jankurai/migration-report.json","purpose":"db"},"agent/":{"command":"just score","purpose":"agent"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "proofmark-rust"
command = "cargo test -p fixture"
purpose = "proofmark"

[[lane]]
name = "db-migration-analyze"
command = "cargo run -p jankurai -- migrate . --analyze --json target/jankurai/migration-report.json"
purpose = "migration"

[[lane]]
name = "audit"
command = "just score"
purpose = "audit"
"#,
    )
    .unwrap();
    repo
}

#[test]
fn authz_rust_change_emits_critical_obligation() {
    let repo = seed_repo();
    fs::write(
        repo.path().join("src/auth.rs"),
        "pub fn authorize(tenant_id: &str) -> bool { !tenant_id.is_empty() }\n",
    )
    .unwrap();
    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/auth.rs")],
        changed_from: None,
        mode: ProofBindMode::Advisory,
        proof_receipts: None,
    })
    .unwrap();
    assert!(output
        .witness
        .surfaces
        .iter()
        .any(|surface| surface.surface_type == "authz_boundary"));
    assert!(output.obligations.obligations.iter().any(|obligation| {
        obligation
            .rule_ids
            .contains(&"HLT-022-AUTHZ-ISOLATION-GAP".to_string())
            && obligation.severity == "critical"
    }));
    assert_eq!(output.obligations.summary.high_or_critical_missing, 1);
}

#[test]
fn proofmark_receipt_alone_does_not_satisfy_matching_obligation() {
    let repo = seed_repo();
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn api() -> bool { true }\n",
    )
    .unwrap();
    let initial = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/lib.rs")],
        changed_from: None,
        mode: ProofBindMode::Advisory,
        proof_receipts: None,
    })
    .unwrap();
    let obligation_id = initial.obligations.obligations[0].obligation_id.clone();
    let receipt_dir = repo.path().join("target/jankurai/proofmark");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("proof-receipt.json"),
        serde_json::json!({
            "lane": "proofmark-rust",
            "command": "jankurai proofmark rust",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["src/lib.rs"],
            "rules_covered": [{"rule_id":"HLT-007-HANDWRITTEN-CONTRACT","status":"covered"}],
            "extensions": {
                "proofmark": {
                    "satisfied_obligations": [obligation_id]
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/lib.rs")],
        changed_from: None,
        mode: ProofBindMode::Advisory,
        proof_receipts: Some(PathBuf::from("target/jankurai/proofmark")),
    })
    .unwrap();
    assert_eq!(output.obligations.summary.satisfied, 0);
    assert_eq!(output.obligations.summary.missing, 1);
}

#[test]
fn typed_test_receipt_must_be_bound_to_the_declared_test_command() {
    let repo = seed_repo();
    fs::create_dir_all(repo.path().join("tests")).unwrap();
    fs::write(
        repo.path().join("tests/integration.rs"),
        "#[test]\nfn exercises_api() {}\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/owner-map.json"),
        r#"{"workspace":"fixture","owners":{"src/":"tools","tests/":"tools","agent/":"agent"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"tests/":{"command":"cargo test --test integration","purpose":"integration"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "integration-test"
command = "cargo test --test integration"
purpose = "test execution"
"#,
    )
    .unwrap();

    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("self-asserted.json"),
        serde_json::json!({
            "lane": "integration-test",
            "command": "true",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["tests/integration.rs"],
            "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}],
            "extensions": {
                "test_execution": {
                    "kind": "test",
                    "status": "pass"
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("tests/integration.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();

    assert_eq!(output.obligations.summary.satisfied, 0);
    assert_eq!(output.obligations.summary.missing, 1);
}

#[test]
fn changed_example_accepts_a_typed_example_receipt_on_its_declared_lane() {
    let repo = seed_repo();
    fs::create_dir_all(repo.path().join("examples")).unwrap();
    fs::write(
        repo.path().join("examples/demo.rs"),
        "fn main() { println!(\"demo\"); }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/owner-map.json"),
        r#"{"workspace":"fixture","owners":{"examples/":"tools"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"examples/":{"command":"cargo run --example demo","purpose":"example"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "example-demo"
command = "cargo run --example demo"
purpose = "example execution"
"#,
    )
    .unwrap();

    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("example.json"),
        serde_json::json!({
            "lane": "example-demo",
            "command": "cargo run --example demo",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["examples/demo.rs"],
            "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}],
            "extensions": {
                "test_execution": {
                    "kind": "example",
                    "status": "pass"
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("examples/demo.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();

    assert_eq!(
        output.obligations.summary.satisfied, 0,
        "file-loaded example receipt cannot manufacture coverage"
    );
    assert!(output.obligations.summary.missing > 0);
}

#[test]
fn non_rust_fallback_requires_the_declared_test_map_command() {
    let repo = seed_repo();
    // Non-inert, non-doc path: still gets catch-all business_invariant when unclassified.
    fs::create_dir_all(repo.path().join("ops")).unwrap();
    fs::write(
        repo.path().join("ops/release-checklist.yaml"),
        "steps: []\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/owner-map.json"),
        r#"{"workspace":"fixture","owners":{"ops/":"ops"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"ops/":{"command":"just ops-check","purpose":"ops"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "ops-check"
command = "just ops-check"
purpose = "ops verification"
"#,
    )
    .unwrap();

    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("ops.json"),
        serde_json::json!({
            "lane": "ops-check",
            "command": "true",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["ops/release-checklist.yaml"],
            "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}]
        })
        .to_string(),
    )
    .unwrap();

    let false_green = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("ops/release-checklist.yaml")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();
    assert_eq!(
        false_green.obligations.obligations[0].required_lanes,
        ["ops-check"]
    );
    assert_eq!(false_green.obligations.summary.satisfied, 0);

    fs::write(
        receipt_dir.join("ops.json"),
        serde_json::json!({
            "lane": "ops-check",
            "command": "just ops-check",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["ops/release-checklist.yaml"],
            "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}]
        })
        .to_string(),
    )
    .unwrap();
    let bound = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("ops/release-checklist.yaml")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();
    assert_eq!(
        bound.obligations.summary.satisfied, 0,
        "file-loaded ops receipt cannot manufacture coverage"
    );
    assert!(bound.obligations.summary.missing > 0);
}

#[test]
fn exact_proofmark_id_does_not_bypass_other_required_lanes() {
    let repo = seed_repo();
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn api() -> bool { true }\n",
    )
    .unwrap();
    let initial = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/lib.rs")],
        changed_from: None,
        mode: ProofBindMode::Advisory,
        proof_receipts: None,
    })
    .unwrap();
    let obligation_id = initial.obligations.obligations[0].obligation_id.clone();
    let receipt_dir = repo.path().join("target/jankurai/proofmark");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("proof-receipt.json"),
        serde_json::json!({
            "lane": "proofmark-rust",
            "command": "jankurai proofmark rust",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["src/lib.rs"],
            "rules_covered": [{"rule_id":"HLT-007-HANDWRITTEN-CONTRACT","status":"covered"}],
            "extensions": {
                "proofmark": {
                    "satisfied_obligations": [obligation_id],
                    "obligation_results": [{
                        "obligation_id": obligation_id,
                        "status": "pass",
                        "negative_proof_status": "not_required"
                    }]
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/lib.rs")],
        changed_from: None,
        mode: ProofBindMode::Advisory,
        proof_receipts: Some(PathBuf::from("target/jankurai/proofmark")),
    })
    .unwrap();
    assert_eq!(output.obligations.summary.satisfied, 0);
    assert_eq!(output.obligations.summary.missing, 1);
}

#[test]
fn every_required_lane_and_receipt_kind_must_be_present() {
    let repo = seed_repo();
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn api() -> bool { true }\n",
    )
    .unwrap();
    let initial = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/lib.rs")],
        changed_from: None,
        mode: ProofBindMode::Advisory,
        proof_receipts: None,
    })
    .unwrap();
    let obligation_id = initial.obligations.obligations[0].obligation_id.clone();
    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("contract.json"),
        serde_json::json!({
            "lane": "contract",
            "command": "cargo public-api diff",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["src/lib.rs"],
            "rules_covered": [{"rule_id":"HLT-007-HANDWRITTEN-CONTRACT","status":"covered"}]
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        receipt_dir.join("proofmark.json"),
        serde_json::json!({
            "lane": "proofmark-rust",
            "command": "jankurai proofmark rust",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["src/lib.rs"],
            "rules_covered": [{"rule_id":"HLT-007-HANDWRITTEN-CONTRACT","status":"covered"}],
            "extensions": {
                "proofmark": {
                    "satisfied_obligations": [obligation_id],
                    "obligation_results": [{
                        "obligation_id": obligation_id,
                        "status": "pass",
                        "negative_proof_status": "not_required"
                    }]
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/lib.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();

    assert_eq!(
        output.obligations.summary.satisfied, 0,
        "file-loaded receipts cannot manufacture coverage"
    );
    assert!(output.obligations.summary.missing > 0);
}

#[test]
fn boundary_obligation_requires_every_receipt_kind() {
    let repo = seed_repo();
    fs::write(
        repo.path().join("src/auth.rs"),
        "pub fn authorize(tenant_id: &str) -> bool { !tenant_id.is_empty() }\n",
    )
    .unwrap();
    let initial = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/auth.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();
    let obligation = initial
        .obligations
        .obligations
        .iter()
        .find(|obligation| {
            obligation
                .rule_ids
                .contains(&"HLT-022-AUTHZ-ISOLATION-GAP".to_string())
        })
        .unwrap();
    let obligation_id = obligation.obligation_id.clone();
    assert!(obligation
        .required_receipt_kinds
        .contains(&"negative-behavior-proof".to_string()));

    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    fs::write(
        receipt_dir.join("security.json"),
        serde_json::json!({
            "lane": "security",
            "command": "cargo test authz",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["src/auth.rs"],
            "rules_covered": [{"rule_id":"HLT-022-AUTHZ-ISOLATION-GAP","status":"covered"}]
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        receipt_dir.join("proofmark.json"),
        serde_json::json!({
            "lane": "proofmark-rust",
            "command": "jankurai proofmark rust",
            "exit_code": 0,
            "elapsed_ms": 1,
            "artifacts": [],
            "changed_paths": ["src/auth.rs"],
            "rules_covered": [{"rule_id":"HLT-022-AUTHZ-ISOLATION-GAP","status":"covered"}],
            "extensions": {
                "proofmark": {
                    "obligation_results": [{
                        "obligation_id": obligation_id,
                        "status": "pass",
                        "negative_proof_status": "missing"
                    }]
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/auth.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
    })
    .unwrap();
    let authz = output
        .obligations
        .obligations
        .iter()
        .find(|obligation| obligation.obligation_id == obligation_id)
        .unwrap();
    assert!(!authz.satisfied);
}

#[test]
fn agent_tool_receipt_requires_authenticated_unique_rule_binding() {
    let repo = seed_repo();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"agent/":{"command":"cargo test --test agent_contract","purpose":"agent tool contract"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "agent-contract"
command = "cargo test --test agent_contract"
purpose = "agent tool contract"
rules_covered = ["HLT-024-AGENT-TOOL-SUPPLY-GAP"]
"#,
    )
    .unwrap();
    fs::create_dir_all(repo.path().join("agent/tools")).unwrap();
    fs::write(
        repo.path().join("agent/tools/tool.sh"),
        "#!/usr/bin/env bash\nset -euo pipefail\necho agent-tool\n",
    )
    .unwrap();

    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    let receipt_path = receipt_dir.join("agent-contract.json");
    let valid_receipt = serde_json::json!({
        "lane": "agent-contract",
        "command": "cargo test --test agent_contract",
        "exit_code": 0,
        "elapsed_ms": 1,
        "artifacts": [],
        "changed_paths": ["agent/tools/tool.sh"],
        "rules_covered": [{
            "rule_id": "HLT-024-AGENT-TOOL-SUPPLY-GAP",
            "status": "covered"
        }]
    });
    let verify = || {
        build_proofbind(ProofBindRequest {
            repo_root: repo.path().to_path_buf(),
            changed_paths: vec![PathBuf::from("agent/tools/tool.sh")],
            changed_from: None,
            mode: ProofBindMode::Required,
            proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
        })
        .unwrap()
    };

    fs::write(&receipt_path, valid_receipt.to_string()).unwrap();
    let valid = verify();
    let tool = valid
        .obligations
        .obligations
        .iter()
        .find(|obligation| obligation.rule_ids == ["HLT-024-AGENT-TOOL-SUPPLY-GAP"])
        .expect("agent tool obligation remains required");
    assert_eq!(tool.required_lanes, ["agent-contract"]);
    let process = valid
        .obligations
        .obligations
        .iter()
        .find(|obligation| obligation.surface_type == "unsafe_or_process_sink")
        .expect("shell process boundary remains independently required");
    assert_eq!(process.required_lanes, ["security"]);
    assert!(!tool.satisfied && !process.satisfied);
    assert_eq!(
        valid.obligations.summary.satisfied, 0,
        "file-loaded agent-tool receipt cannot manufacture coverage"
    );

    let invalid_rule_claims = [
        (
            "missing",
            serde_json::json!({
                "lane": "agent-contract",
                "command": "cargo test --test agent_contract",
                "exit_code": 0,
                "elapsed_ms": 1,
                "artifacts": [],
                "changed_paths": ["agent/tools/tool.sh"]
            }),
        ),
        (
            "legacy string",
            serde_json::json!({
                "lane": "agent-contract",
                "command": "cargo test --test agent_contract",
                "exit_code": 0,
                "elapsed_ms": 1,
                "artifacts": [],
                "changed_paths": ["agent/tools/tool.sh"],
                "rules_covered": ["HLT-024-AGENT-TOOL-SUPPLY-GAP"]
            }),
        ),
        (
            "duplicate",
            serde_json::json!({
                "lane": "agent-contract",
                "command": "cargo test --test agent_contract",
                "exit_code": 0,
                "elapsed_ms": 1,
                "artifacts": [],
                "changed_paths": ["agent/tools/tool.sh"],
                "rules_covered": [
                    {
                        "rule_id": "HLT-024-AGENT-TOOL-SUPPLY-GAP",
                        "status": "covered"
                    },
                    {
                        "rule_id": "HLT-024-AGENT-TOOL-SUPPLY-GAP",
                        "status": "covered"
                    }
                ]
            }),
        ),
        (
            "wrong rule",
            serde_json::json!({
                "lane": "agent-contract",
                "command": "cargo test --test agent_contract",
                "exit_code": 0,
                "elapsed_ms": 1,
                "artifacts": [],
                "changed_paths": ["agent/tools/tool.sh"],
                "rules_covered": [{
                    "rule_id": "HLT-023-INPUT-BOUNDARY-GAP",
                    "status": "covered"
                }]
            }),
        ),
        (
            "partially valid",
            serde_json::json!({
                "lane": "agent-contract",
                "command": "cargo test --test agent_contract",
                "exit_code": 0,
                "elapsed_ms": 1,
                "artifacts": [],
                "changed_paths": ["agent/tools/tool.sh"],
                "rules_covered": [
                    {
                        "rule_id": "HLT-024-AGENT-TOOL-SUPPLY-GAP",
                        "status": "covered"
                    },
                    {
                        "rule_id": "HLT-023-INPUT-BOUNDARY-GAP",
                        "status": "review"
                    }
                ]
            }),
        ),
        (
            "unrelated path",
            serde_json::json!({
                "lane": "agent-contract",
                "command": "cargo test --test agent_contract",
                "exit_code": 0,
                "elapsed_ms": 1,
                "artifacts": [],
                "changed_paths": ["README.md"],
                "rules_covered": [{
                    "rule_id": "HLT-024-AGENT-TOOL-SUPPLY-GAP",
                    "status": "covered"
                }]
            }),
        ),
        (
            "unrelated command",
            serde_json::json!({
                "lane": "agent-contract",
                "command": "true",
                "exit_code": 0,
                "elapsed_ms": 1,
                "artifacts": [],
                "changed_paths": ["agent/tools/tool.sh"],
                "rules_covered": [{
                    "rule_id": "HLT-024-AGENT-TOOL-SUPPLY-GAP",
                    "status": "covered"
                }]
            }),
        ),
    ];
    for (case, receipt) in invalid_rule_claims {
        fs::write(&receipt_path, receipt.to_string()).unwrap();
        assert_eq!(
            verify().obligations.summary.satisfied,
            0,
            "{case} rule claim must fail closed"
        );
    }

    fs::write(&receipt_path, valid_receipt.to_string()).unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "agent-contract"
command = "cargo test --test agent_contract"
purpose = "agent tool contract"
"#,
    )
    .unwrap();
    assert_eq!(
        verify().obligations.summary.satisfied,
        0,
        "a receipt cannot self-assert a rule absent from the reviewed lane declaration"
    );

    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "agent-contract"
command = "cargo test --test agent_contract"
purpose = "agent tool contract"
rules_covered = [
  "HLT-024-AGENT-TOOL-SUPPLY-GAP",
  "HLT-024-AGENT-TOOL-SUPPLY-GAP",
]
"#,
    )
    .unwrap();
    assert_eq!(
        verify().obligations.summary.satisfied,
        0,
        "duplicate reviewed rule declarations must fail closed"
    );
}

#[test]
fn documentation_and_inert_paths_are_not_agent_tool_surfaces() {
    let repo = seed_repo();
    fs::create_dir_all(repo.path().join("docs")).unwrap();
    fs::create_dir_all(repo.path().join("agent/baselines")).unwrap();
    fs::create_dir_all(repo.path().join("schemas")).unwrap();
    fs::create_dir_all(repo.path().join("agent/tools")).unwrap();
    fs::write(
        repo.path().join("README.md"),
        "# Fixture\n\nThis document mentions tool supply and mcp in prose only.\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("docs/architecture.md"),
        "Operators run tools; mcp bridges are described here.\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/baselines/repo-score.json"),
        r#"{"tool":"score","mcp":false}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("schemas/proofbind-witness.schema.json"),
        r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"witness"}"#,
    )
    .unwrap();
    // Negative control: executable under docs/ must stay a tool/API surface.
    fs::write(
        repo.path().join("docs/tool.rs"),
        "pub fn run_tool() {}\nfn main() { let _ = std::process::Command::new(\"true\"); }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("docs/mcp_handler.mjs"),
        "export function mcpTool() { return 'ok'; }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/tools/security-lane.sh"),
        "#!/usr/bin/env bash\nset -euo pipefail\necho security-lane\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/tool-contract.md"),
        "# Agent tool contract\n\nMarkdown under agent/ is still prose, not an executable handler.\n",
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![
            PathBuf::from("README.md"),
            PathBuf::from("docs/architecture.md"),
            PathBuf::from("agent/baselines/repo-score.json"),
            PathBuf::from("schemas/proofbind-witness.schema.json"),
            PathBuf::from("docs/tool.rs"),
            PathBuf::from("docs/mcp_handler.mjs"),
            PathBuf::from("agent/tools/security-lane.sh"),
            PathBuf::from("agent/tool-contract.md"),
        ],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();

    let tool_paths: Vec<_> = output
        .witness
        .surfaces
        .iter()
        .filter(|surface| {
            surface.surface_type == "cli_command" || surface.surface_type == "mcp_tool"
        })
        .map(|surface| surface.path.as_str())
        .collect();
    assert!(
        !tool_paths.iter().any(|path| {
            *path == "README.md"
                || *path == "docs/architecture.md"
                || *path == "agent/baselines/repo-score.json"
                || *path == "schemas/proofbind-witness.schema.json"
                || *path == "agent/tool-contract.md"
        }),
        "inert md/json must not become cli_command/mcp_tool: {tool_paths:?}"
    );
    assert!(
        tool_paths.contains(&"docs/mcp_handler.mjs"),
        "docs/*.mjs executable must remain tool surfaces: {tool_paths:?}"
    );
    assert!(
        tool_paths.contains(&"agent/tools/security-lane.sh"),
        "agent/tools/*.sh must remain tool surfaces: {tool_paths:?}"
    );
    // docs/tool.rs must remain executable (rust_public_api), never inert-skipped.
    assert!(
        output.witness.surfaces.iter().any(|surface| {
            surface.path == "docs/tool.rs" && surface.surface_type == "rust_public_api"
        }),
        "docs/tool.rs must remain an executable rust surface"
    );
}

#[test]
fn agent_control_toml_is_not_cli_command_or_hlt024() {
    let repo = seed_repo();
    // seed_repo already writes agent/proof-lanes.toml; treat it as the changed path.
    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("agent/proof-lanes.toml")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();

    assert!(
        output.witness.surfaces.iter().any(|surface| {
            surface.path == "agent/proof-lanes.toml"
                && (surface.surface_type == "business_invariant"
                    || surface.surface_type == "pipeline_authority")
                && surface
                    .required_rules
                    .contains(&"HLT-008-FALSE-GREEN-RISK".to_string())
        }),
        "proof-lanes command authority must keep HLT-008: {:?}",
        output.witness.surfaces
    );
    assert!(
        !output.obligations.obligations.iter().any(|obligation| {
            obligation
                .rule_ids
                .iter()
                .any(|rule| rule.contains("HLT-024"))
                || obligation.surface_type == "cli_command"
                || obligation.surface_type == "mcp_tool"
                || matches!(obligation.severity.as_str(), "high" | "critical")
        }),
        "agent/proof-lanes.toml must not require HLT-024 or high/critical obligations: {:?}",
        output.obligations.obligations
    );
    assert_eq!(output.obligations.summary.high_or_critical_missing, 0);
}

#[test]
fn ops_ci_shell_scripts_keep_hlt020_and_changed_behavior() {
    let repo = seed_repo();
    fs::create_dir_all(repo.path().join("ops/ci")).unwrap();
    fs::create_dir_all(repo.path().join("tools")).unwrap();
    fs::write(
        repo.path().join("ops/ci/foo.sh"),
        "#!/usr/bin/env bash\nset -euo pipefail\necho ci-foo\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("ops/ci/github-setup.sh"),
        "#!/usr/bin/env bash\nset -euo pipefail\necho bootstrap\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("tools/bar.sh"),
        "#!/usr/bin/env bash\nset -euo pipefail\necho agent-tool\n",
    )
    .unwrap();

    let ops = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![
            PathBuf::from("ops/ci/foo.sh"),
            PathBuf::from("ops/ci/github-setup.sh"),
        ],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();

    for path in ["ops/ci/foo.sh", "ops/ci/github-setup.sh"] {
        let rules: Vec<_> = ops
            .witness
            .surfaces
            .iter()
            .filter(|surface| surface.path == path)
            .flat_map(|surface| surface.required_rules.iter().cloned())
            .collect();
        assert!(
            ops.witness
                .surfaces
                .iter()
                .any(|surface| { surface.path == path && surface.surface_type == "ci_hardening" }),
            "{path} must keep ci_hardening: {:?}",
            ops.witness.surfaces
        );
        assert!(
            rules.contains(&"HLT-020-CI-HARDENING-GAP".to_string()),
            "{path} must require HLT-020: {rules:?}"
        );
        assert!(
            rules.contains(&"HLT-008-FALSE-GREEN-RISK".to_string()),
            "{path} must keep additive HLT-008: {rules:?}"
        );
        assert!(
            ops.witness.surfaces.iter().any(|surface| {
                surface.path == path && surface.required_lanes.contains(&"security".to_string())
            }),
            "{path} must require security lane: {:?}",
            ops.witness.surfaces
        );
    }

    let tools = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("tools/bar.sh")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();
    assert!(
        tools.witness.surfaces.iter().any(|surface| {
            surface.path == "tools/bar.sh"
                && surface.surface_type == "cli_command"
                && surface
                    .required_rules
                    .contains(&"HLT-024-AGENT-TOOL-SUPPLY-GAP".to_string())
        }),
        "tools/bar.sh must stay agent-tool HLT-024: {:?}",
        tools.witness.surfaces
    );
    assert!(
        tools.witness.surfaces.iter().any(|surface| {
            surface.path == "tools/bar.sh"
                && surface
                    .risk_tags
                    .iter()
                    .any(|tag| tag == "changed_behavior")
        }),
        "real tools must keep changed_behavior: {:?}",
        tools.witness.surfaces
    );
}

#[test]
fn executable_toml_tool_policy_is_classified_by_behavior() {
    let repo = seed_repo();
    fs::create_dir_all(repo.path().join("tools")).unwrap();
    fs::create_dir_all(repo.path().join("agent")).unwrap();
    fs::write(
        repo.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nserde = \"1\"\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("Cargo.name-only.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("comment-only.toml"),
        "# [[lane]]\n# command = \"cargo test\"\n# [dependencies]\n# serde = \"1\"\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.97.1\"\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/audit-policy.toml"),
        "minimum_score = 80\nfail_on = []\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("tools/mcp-policy.toml"),
        "[mcp.servers.fs]\ncommand = \"npx\"\nargs = [\"-y\", \"@modelcontextprotocol/server-filesystem\"]\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("tools/agent-tools.toml"),
        "[[tool]]\nname = \"search\"\ncommand = \"tools/search.sh\"\n",
    )
    .unwrap();

    let authority = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![
            PathBuf::from("Cargo.toml"),
            PathBuf::from("rust-toolchain.toml"),
            PathBuf::from("agent/audit-policy.toml"),
            PathBuf::from("agent/proof-lanes.toml"),
        ],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();
    for path in [
        "Cargo.toml",
        "rust-toolchain.toml",
        "agent/audit-policy.toml",
        "agent/proof-lanes.toml",
    ] {
        assert!(
            authority.witness.surfaces.iter().any(|surface| {
                surface.path == path
                    && (surface.surface_type == "business_invariant"
                        || surface.surface_type == "pipeline_authority")
                    && surface
                        .required_rules
                        .contains(&"HLT-008-FALSE-GREEN-RISK".to_string())
                    && !surface
                        .required_rules
                        .contains(&"HLT-024-AGENT-TOOL-SUPPLY-GAP".to_string())
            }),
            "{path} command/policy authority must emit HLT-008, not HLT-024: {:?}",
            authority.witness.surfaces
        );
    }

    let inert = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![
            PathBuf::from("Cargo.name-only.toml"),
            PathBuf::from("comment-only.toml"),
        ],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();
    assert!(
        inert.witness.surfaces.is_empty(),
        "comment-only or name-only package TOML must stay inert, got {:?}",
        inert.witness.surfaces
    );

    let executable = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![
            PathBuf::from("tools/mcp-policy.toml"),
            PathBuf::from("tools/agent-tools.toml"),
        ],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();
    for path in ["tools/mcp-policy.toml", "tools/agent-tools.toml"] {
        assert!(
            executable.witness.surfaces.iter().any(|surface| {
                surface.path == path
                    && (surface.surface_type == "cli_command" || surface.surface_type == "mcp_tool")
                    && surface
                        .required_rules
                        .contains(&"HLT-024-AGENT-TOOL-SUPPLY-GAP".to_string())
            }),
            "{path} executable TOML must be a tool surface: {:?}",
            executable.witness.surfaces
        );
        assert!(
            !executable.witness.surfaces.iter().any(|surface| {
                surface.path == path
                    && surface
                        .required_rules
                        .contains(&"HLT-008-FALSE-GREEN-RISK".to_string())
                    && surface.surface_type == "business_invariant"
            }),
            "{path} must not fall back to HLT-008: {:?}",
            executable.witness.surfaces
        );
    }
}

#[test]
fn real_tools_preserve_input_and_authorization_obligations() {
    let repo = seed_repo();
    fs::create_dir_all(repo.path().join("tools")).unwrap();
    fs::create_dir_all(repo.path().join("docs")).unwrap();
    fs::write(
        repo.path().join("tools/gate.sh"),
        "#!/usr/bin/env bash\n# authorize tenant isolation\nparse() { :; }\nauthorize() { :; }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("docs/handler.mjs"),
        "export function authorize(tenant_id) { return parse(tenant_id); }\n",
    )
    .unwrap();

    let output = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![
            PathBuf::from("tools/gate.sh"),
            PathBuf::from("docs/handler.mjs"),
        ],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .unwrap();

    for path in ["tools/gate.sh", "docs/handler.mjs"] {
        assert!(
            output.witness.surfaces.iter().any(|surface| {
                surface.path == path
                    && (surface.surface_type == "cli_command" || surface.surface_type == "mcp_tool")
                    && surface
                        .required_rules
                        .contains(&"HLT-024-AGENT-TOOL-SUPPLY-GAP".to_string())
                    && surface
                        .risk_tags
                        .iter()
                        .any(|tag| tag == "changed_behavior")
            }),
            "{path} must remain an agent tool with changed_behavior: {:?}",
            output.witness.surfaces
        );
        assert!(
            output.witness.surfaces.iter().any(|surface| {
                surface.path == path
                    && surface.surface_type == "authz_boundary"
                    && surface
                        .required_rules
                        .contains(&"HLT-022-AUTHZ-ISOLATION-GAP".to_string())
            }),
            "{path} must keep authorization obligation: {:?}",
            output.witness.surfaces
        );
        assert!(
            output.witness.surfaces.iter().any(|surface| {
                surface.path == path
                    && surface.surface_type == "input_boundary"
                    && surface
                        .required_rules
                        .contains(&"HLT-023-INPUT-BOUNDARY-GAP".to_string())
            }),
            "{path} must keep input obligation: {:?}",
            output.witness.surfaces
        );
    }
}

#[test]
fn imported_receipt_cannot_manufacture_coverage() {
    let repo = seed_repo();
    fs::create_dir_all(repo.path().join("examples")).unwrap();
    fs::write(
        repo.path().join("examples/demo.rs"),
        "fn main() { println!(\"demo\"); }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/owner-map.json"),
        r#"{"workspace":"fixture","owners":{"examples/":"tools"}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/test-map.json"),
        r#"{"workspace":"fixture","tests":{"examples/":{"command":"cargo run --example demo","purpose":"example"}}}"#,
    )
    .unwrap();
    fs::write(
        repo.path().join("agent/proof-lanes.toml"),
        r#"[[lane]]
name = "example-demo"
command = "cargo run --example demo"
purpose = "example execution"
"#,
    )
    .unwrap();

    let receipt_dir = repo.path().join("target/jankurai/receipts");
    fs::create_dir_all(&receipt_dir).unwrap();
    let typed = serde_json::json!({
        "kind": "example",
        "status": "pass"
    });
    let variants = [
        (
            "marked-imported",
            serde_json::json!({
                "lane": "example-demo",
                "command": "cargo run --example demo",
                "exit_code": 0,
                "elapsed_ms": 1,
                "artifacts": [],
                "changed_paths": ["examples/demo.rs"],
                "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}],
                "imported": true,
                "extensions": {
                    "imported": true,
                    "source": "imported",
                    "test_execution": typed
                }
            }),
        ),
        (
            "no-imported-markers",
            serde_json::json!({
                "lane": "example-demo",
                "command": "cargo run --example demo",
                "exit_code": 0,
                "elapsed_ms": 1,
                "artifacts": [],
                "changed_paths": ["examples/demo.rs"],
                "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}],
                "extensions": {
                    "test_execution": typed
                }
            }),
        ),
        (
            "imported-false-source-local",
            serde_json::json!({
                "lane": "example-demo",
                "command": "cargo run --example demo",
                "exit_code": 0,
                "elapsed_ms": 1,
                "artifacts": [],
                "changed_paths": ["examples/demo.rs"],
                "rules_covered": [{"rule_id":"HLT-008-FALSE-GREEN-RISK","status":"covered"}],
                "imported": false,
                "extensions": {
                    "imported": false,
                    "source": "local",
                    "test_execution": typed
                }
            }),
        ),
    ];
    for (label, receipt) in variants {
        fs::write(receipt_dir.join("imported.json"), receipt.to_string()).unwrap();
        let output = build_proofbind(ProofBindRequest {
            repo_root: repo.path().to_path_buf(),
            changed_paths: vec![PathBuf::from("examples/demo.rs")],
            changed_from: None,
            mode: ProofBindMode::Required,
            proof_receipts: Some(PathBuf::from("target/jankurai/receipts")),
        })
        .unwrap();
        assert_eq!(
            output.obligations.summary.satisfied, 0,
            "{label} file-loaded receipt must not manufacture coverage: {:?}",
            output.obligations.obligations
        );
        assert!(output.obligations.summary.missing > 0, "{label}");
    }
}

fn git(repo: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(repo)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

fn committed_fixture() -> tempfile::TempDir {
    let repo = seed_repo();
    fs::create_dir_all(repo.path().join("ops/ci")).unwrap();
    fs::write(
        repo.path().join("src/auth.rs"),
        "pub fn authorize(tenant_id: &str) -> bool { !tenant_id.is_empty() }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("src/api.rs"),
        "pub fn api() -> bool { true }\n",
    )
    .unwrap();
    fs::write(
        repo.path().join("ops/ci/security.sh"),
        "#!/usr/bin/env bash\nset -euo pipefail\ncargo audit\n",
    )
    .unwrap();
    fs::write(repo.path().join("README.md"), "# fixture\n").unwrap();
    git(repo.path(), &["init", "-q", "-b", "main"]);
    git(repo.path(), &["add", "-A"]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);
    git(repo.path(), &["branch", "base"]);
    repo
}

fn request(
    repo: &std::path::Path,
    changed_from: Option<&str>,
    mode: ProofBindMode,
) -> ProofBindRequest {
    ProofBindRequest {
        repo_root: repo.to_path_buf(),
        changed_paths: vec![],
        changed_from: changed_from.map(str::to_string),
        mode,
        proof_receipts: None,
    }
}

fn surface_types(output: &jankurai_proofbind::ProofBindOutput, path: &str) -> Vec<String> {
    output
        .witness
        .surfaces
        .iter()
        .filter(|surface| surface.path == path)
        .map(|surface| format!("{}:{}", surface.surface_type, surface.symbol))
        .collect()
}

fn removal_bound(output: &jankurai_proofbind::ProofBindOutput, path: &str) -> bool {
    output.obligations.obligations.iter().any(|obligation| {
        obligation.path == path
            && obligation.risk_tags.iter().any(|tag| tag == "removal")
            && obligation.rule_ids == ["HLT-008-FALSE-GREEN-RISK"]
            && !obligation.satisfied
    })
}

// Deleting a required input is a change to prove. The deleted file is
// classified from its pre-image, so removing an authorization module binds the
// same critical HLT-022 obligation editing it would, plus a removal obligation.
// A deletion-only change set cannot pass Required mode with zero obligations.
#[test]
fn deletion_only_change_set_binds_obligations_and_does_not_pass() {
    let repo = committed_fixture();
    git(
        repo.path(),
        &["rm", "-q", "src/auth.rs", "ops/ci/security.sh"],
    );
    git(
        repo.path(),
        &["commit", "-q", "-m", "remove auth and CI hardening"],
    );

    let output = build_proofbind(request(repo.path(), Some("base"), ProofBindMode::Required))
        .expect("a diff that only deletes files is analyzable");
    assert_eq!(
        output.witness.changed_paths,
        vec!["ops/ci/security.sh".to_string(), "src/auth.rs".to_string()]
    );
    let auth = surface_types(&output, "src/auth.rs");
    assert!(
        auth.contains(&"authz_boundary:authz".to_string()),
        "{auth:?}"
    );
    assert!(
        auth.contains(&"business_invariant:removal".to_string()),
        "{auth:?}"
    );
    let ci = surface_types(&output, "ops/ci/security.sh");
    assert!(ci.contains(&"ci_hardening:ci".to_string()), "{ci:?}");
    assert!(removal_bound(&output, "src/auth.rs"));
    assert!(removal_bound(&output, "ops/ci/security.sh"));
    let summary = &output.obligations.summary;
    assert!(summary.total > 0 && summary.missing == summary.total);
    assert!(summary.high_or_critical_missing > 0);
    assert_eq!(summary.verdict, "block");
}

// Even a path whose pre-image classifies as inert (documentation) binds its
// removal obligation: a non-empty change set never yields an empty obligation set.
#[test]
fn deleting_an_inert_file_still_binds_a_removal_obligation() {
    let repo = committed_fixture();
    git(repo.path(), &["rm", "-q", "README.md"]);
    git(repo.path(), &["commit", "-q", "-m", "remove readme"]);

    let output = build_proofbind(request(repo.path(), Some("base"), ProofBindMode::Required))
        .expect("analyzable");
    assert_eq!(
        surface_types(&output, "README.md"),
        vec!["business_invariant:removal".to_string()]
    );
    assert!(removal_bound(&output, "README.md"));
    assert_eq!(output.obligations.summary.total, 1);
    assert_ne!(output.obligations.summary.verdict, "pass");
}

// A deletion alongside an ordinary edit binds both: the edit from the working
// tree, the deletion from its pre-image plus its removal obligation.
#[test]
fn deletion_alongside_real_changes_binds_both() {
    let repo = committed_fixture();
    git(repo.path(), &["rm", "-q", "src/auth.rs"]);
    fs::write(
        repo.path().join("src/api.rs"),
        "pub fn api() -> bool { false }\n",
    )
    .unwrap();
    git(
        repo.path(),
        &["commit", "-q", "-am", "remove auth, change api"],
    );

    let output = build_proofbind(request(repo.path(), Some("base"), ProofBindMode::Advisory))
        .expect("analyzable");
    assert_eq!(
        output.witness.changed_paths,
        vec!["src/api.rs".to_string(), "src/auth.rs".to_string()]
    );
    let api = surface_types(&output, "src/api.rs");
    assert!(api.contains(&"rust_public_api:api".to_string()), "{api:?}");
    assert!(!api.iter().any(|surface| surface.ends_with(":removal")));
    let auth = surface_types(&output, "src/auth.rs");
    assert!(
        auth.contains(&"authz_boundary:authz".to_string()),
        "{auth:?}"
    );
    assert!(removal_bound(&output, "src/auth.rs"));
}

// Working-tree deletions (staged or not) are classified from the index or
// HEAD pre-image. A path named explicitly with --changed carries no deletion
// status, so a missing one is still a required input: the typo guard.
#[test]
fn working_tree_deletion_binds_obligations_and_explicit_missing_path_still_fails() {
    let repo = committed_fixture();
    git(repo.path(), &["rm", "-q", "src/auth.rs"]);
    fs::remove_file(repo.path().join("src/api.rs")).unwrap();

    let output = build_proofbind(request(repo.path(), None, ProofBindMode::Required))
        .expect("a working-tree deletion is analyzable");
    assert_eq!(
        output.witness.changed_paths,
        vec!["src/api.rs".to_string(), "src/auth.rs".to_string()]
    );
    assert!(surface_types(&output, "src/auth.rs").contains(&"authz_boundary:authz".to_string()));
    assert!(surface_types(&output, "src/api.rs").contains(&"rust_public_api:api".to_string()));
    assert!(removal_bound(&output, "src/auth.rs"));
    assert!(removal_bound(&output, "src/api.rs"));
    assert_ne!(output.obligations.summary.verdict, "pass");

    let error = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/api.rs")],
        changed_from: None,
        mode: ProofBindMode::Required,
        proof_receipts: None,
    })
    .expect_err("an explicit missing path is a required input");
    assert!(
        format!("{error:#}").contains("required input missing: src/api.rs"),
        "{error:#}"
    );
    let typo = build_proofbind(ProofBindRequest {
        repo_root: repo.path().to_path_buf(),
        changed_paths: vec![PathBuf::from("src/apii.rs")],
        changed_from: None,
        mode: ProofBindMode::Advisory,
        proof_receipts: None,
    })
    .expect_err("a typo is never treated as a removal");
    assert!(format!("{typo:#}").contains("required input missing: src/apii.rs"));
}

// `RD`: renamed in the index, then deleted in the working tree. The rename
// destination is the removed path, and its pre-image comes from the index.
#[test]
fn rename_then_delete_binds_the_destination_removal() {
    let repo = committed_fixture();
    git(repo.path(), &["mv", "src/auth.rs", "src/authz.rs"]);
    fs::remove_file(repo.path().join("src/authz.rs")).unwrap();

    let output =
        build_proofbind(request(repo.path(), None, ProofBindMode::Advisory)).expect("analyzable");
    assert_eq!(
        output.witness.changed_paths,
        vec!["src/authz.rs".to_string()]
    );
    assert!(surface_types(&output, "src/authz.rs").contains(&"authz_boundary:authz".to_string()));
    assert!(removal_bound(&output, "src/authz.rs"));
}

// Git reports a staged deletion, but the path is back in the working tree: it
// is classified from what is there now, with no removal obligation.
#[test]
fn deleted_path_recreated_in_the_working_tree_is_read_not_removed() {
    let repo = committed_fixture();
    git(repo.path(), &["rm", "-q", "--cached", "src/api.rs"]);
    fs::write(
        repo.path().join("src/api.rs"),
        "pub fn replaced() -> bool { true }\n",
    )
    .unwrap();

    let output =
        build_proofbind(request(repo.path(), None, ProofBindMode::Advisory)).expect("analyzable");
    let api = surface_types(&output, "src/api.rs");
    assert!(
        api.contains(&"rust_public_api:replaced".to_string()),
        "{api:?}"
    );
    assert!(
        !api.iter().any(|surface| surface.ends_with(":removal")),
        "{api:?}"
    );
}
