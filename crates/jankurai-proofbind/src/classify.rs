use crate::catalog::Catalog;
use crate::configuration;
use crate::shared::path_symbol;
use crate::surface_rules::{
    contains_authz_marker, contains_destructive_sql, contains_input_marker, contains_process_sink,
    is_agent_tool_surface, is_inert_changed_path, is_ops_ci_shell_script, is_test_or_example_path,
    rust_public_symbols, surface_id,
};
use crate::ChangedSurface;
use anyhow::Result;
use std::path::Path;

pub(crate) fn classify_changed_path(
    repo: &Path,
    catalog: &Catalog,
    path: &str,
) -> Result<Vec<ChangedSurface>> {
    let text = crate::input::read_text(repo, Path::new(path))?;
    classify_text(catalog, path, &text)
}

/// A deleted path binds what its pre-image would bind if edited (removing an
/// authorization module, a policy file or a CI script changes behavior at least
/// as much as editing it), plus one removal obligation that is never inert, so
/// a change set that only deletes files can never pass with zero obligations.
pub(crate) fn classify_removed_path(
    catalog: &Catalog,
    path: &str,
    pre_image: &str,
) -> Result<Vec<ChangedSurface>> {
    let mut surfaces = classify_text(catalog, path, pre_image)?;
    let (_, proof_lane) = catalog.test_for_path(path);
    let required_lane = if path.to_ascii_lowercase().ends_with(".rs") {
        "proofmark-rust"
    } else if proof_lane == "unmapped" {
        "security"
    } else {
        proof_lane.as_str()
    };
    let mut removal = surface(
        catalog,
        path,
        "removal",
        "business_invariant",
        "medium",
        vec!["removal", "changed_behavior"],
        vec!["HLT-008-FALSE-GREEN-RISK"],
        vec![required_lane],
    );
    removal.repair_tasks = vec![
        "prove the removal: run the lane that covered the deleted path and attach a proof receipt"
            .into(),
    ];
    surfaces.push(removal);
    Ok(surfaces)
}

fn classify_text(catalog: &Catalog, path: &str, text: &str) -> Result<Vec<ChangedSurface>> {
    let lower_path = path.to_ascii_lowercase();
    let lower_text = text.to_ascii_lowercase();
    let mut surfaces = Vec::new();

    if let Some(surfaces) = configuration::surfaces(catalog, path, text)? {
        return Ok(surfaces);
    }

    // Docs / inert control data must not become tool surfaces or HLT-008.
    if is_inert_changed_path(&lower_path, text) {
        return Ok(surfaces);
    }

    // CI scripts → additive HLT-020 hardening plus HLT-008 changed-behavior.
    // Continue so authz/input/process checks still run. tools/*.sh stay HLT-024.
    if is_ops_ci_shell_script(&lower_path) {
        surfaces.push(surface(
            catalog,
            path,
            "ci",
            "ci_hardening",
            "high",
            vec!["ci_hardening", "pipeline_authority", "changed_behavior"],
            vec!["HLT-020-CI-HARDENING-GAP", "HLT-008-FALSE-GREEN-RISK"],
            vec!["security"],
        ));
    }

    // A shell program can launch processes and consumes ambient input even if
    // it has no Rust process marker. CI hardening never replaces this boundary.
    if lower_path.ends_with(".sh")
        && text.lines().any(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
    {
        surfaces.push(surface(
            catalog,
            path,
            "process_sink",
            "unsafe_or_process_sink",
            "high",
            vec!["process", "input_validation", "negative_proof_required"],
            vec!["HLT-023-INPUT-BOUNDARY-GAP"],
            vec!["security"],
        ));
    }

    if lower_path.ends_with(".rs") && is_test_or_example_path(&lower_path) {
        let (_, proof_lane) = catalog.test_for_path(path);
        surfaces.push(surface(
            catalog,
            path,
            &path_symbol(path),
            "test_execution",
            "medium",
            vec!["changed_behavior", "typed_test_execution"],
            vec!["HLT-008-FALSE-GREEN-RISK"],
            vec![proof_lane.as_str()],
        ));
        return Ok(surfaces);
    }

    if lower_path.ends_with(".rs") {
        for symbol in rust_public_symbols(text) {
            surfaces.push(surface(
                catalog,
                path,
                &symbol,
                "rust_public_api",
                "medium",
                vec!["public_api"],
                vec!["HLT-007-HANDWRITTEN-CONTRACT"],
                vec!["contract", "proofmark-rust"],
            ));
        }
        if lower_path.ends_with("main.rs")
            || lower_path.contains("/commands/")
            || lower_text.contains("subcommand")
        {
            let symbol = path_symbol(path);
            surfaces.push(surface(
                catalog,
                path,
                &symbol,
                "cli_command",
                "high",
                vec!["tool_surface", "operator_boundary"],
                vec!["HLT-024-AGENT-TOOL-SUPPLY-GAP"],
                vec!["security", "proofmark-rust"],
            ));
        }
        if contains_process_sink(&lower_text) {
            surfaces.push(surface(
                catalog,
                path,
                "process_sink",
                "unsafe_or_process_sink",
                "high",
                vec!["process", "filesystem", "unsafe_sink"],
                vec!["HLT-023-INPUT-BOUNDARY-GAP"],
                vec!["security", "proofmark-rust"],
            ));
        }
    }

    if contains_authz_marker(&lower_path, &lower_text) {
        surfaces.push(surface(
            catalog,
            path,
            "authz",
            "authz_boundary",
            "critical",
            vec![
                "authorization",
                "tenant_isolation",
                "negative_proof_required",
            ],
            vec!["HLT-022-AUTHZ-ISOLATION-GAP"],
            vec!["security", "proofmark-rust"],
        ));
    }
    if contains_input_marker(&lower_path, &lower_text) {
        surfaces.push(surface(
            catalog,
            path,
            "input",
            "input_boundary",
            "high",
            vec!["input_validation", "negative_proof_required"],
            vec!["HLT-023-INPUT-BOUNDARY-GAP"],
            vec!["security", "proofmark-rust"],
        ));
    }

    if lower_path.ends_with(".sql") {
        let destructive = contains_destructive_sql(&lower_text);
        surfaces.push(surface(
            catalog,
            path,
            "sql",
            "sql_query",
            if destructive { "critical" } else { "high" },
            if destructive {
                vec!["sql", "destructive"]
            } else {
                vec!["sql"]
            },
            if destructive {
                vec!["HLT-021-DESTRUCTIVE-MIGRATION"]
            } else {
                vec!["HLT-006-DIRECT-DB-WRONG-LAYER"]
            },
            if destructive {
                vec!["db-migration-analyze"]
            } else {
                vec!["db"]
            },
        ));
        if lower_path.contains("migration") || lower_path.starts_with("db/") {
            surfaces.push(surface(
                catalog,
                path,
                "migration",
                "db_migration",
                if destructive { "critical" } else { "medium" },
                if destructive {
                    vec!["migration", "destructive"]
                } else {
                    vec!["migration"]
                },
                if destructive {
                    vec!["HLT-021-DESTRUCTIVE-MIGRATION"]
                } else {
                    vec!["HLT-006-DIRECT-DB-WRONG-LAYER"]
                },
                vec!["db-migration-analyze"],
            ));
        }
    }

    if is_agent_tool_surface(&lower_path, &lower_text) {
        let (_, proof_lane) = catalog.test_for_path(path);
        let required_lane = if proof_lane == "unmapped" {
            "security"
        } else {
            proof_lane.as_str()
        };
        surfaces.push(surface(
            catalog,
            path,
            "tool",
            if lower_text.contains("mcp") || lower_path.contains("mcp") {
                "mcp_tool"
            } else {
                "cli_command"
            },
            "high",
            vec!["agent_tool_supply", "tool_authority", "changed_behavior"],
            vec!["HLT-024-AGENT-TOOL-SUPPLY-GAP"],
            vec![required_lane],
        ));
    }

    if surfaces.is_empty() {
        let (_, proof_lane) = catalog.test_for_path(path);
        let required_lane = if lower_path.ends_with(".rs") {
            "proofmark-rust"
        } else {
            proof_lane.as_str()
        };
        surfaces.push(surface(
            catalog,
            path,
            &path_symbol(path),
            "business_invariant",
            "medium",
            vec!["changed_behavior"],
            vec!["HLT-008-FALSE-GREEN-RISK"],
            vec![required_lane],
        ));
    }

    Ok(surfaces)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn surface(
    catalog: &Catalog,
    path: &str,
    symbol: &str,
    surface_type: &str,
    severity: &str,
    risk_tags: Vec<&str>,
    required_rules: Vec<&str>,
    required_lanes: Vec<&str>,
) -> ChangedSurface {
    let (owner, owner_route) = catalog.owner_for_path(path);
    let (test_route, proof_lane) = catalog.test_for_path(path);
    ChangedSurface {
        surface_id: surface_id(surface_type, path, symbol),
        path: path.into(),
        symbol: symbol.into(),
        surface_type: surface_type.into(),
        severity: severity.into(),
        risk_tags: risk_tags.into_iter().map(str::to_string).collect(),
        owner,
        owner_route,
        test_route,
        proof_lane,
        required_rules: required_rules.into_iter().map(str::to_string).collect(),
        required_lanes: required_lanes.into_iter().map(str::to_string).collect(),
        repair_tasks: crate::obligations::repair_tasks(surface_type, severity),
    }
}
