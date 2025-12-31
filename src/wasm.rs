//! WebAssembly bindings for the Little Snitch rules generator.

use crate::{
    build_output, get_category_info, load_embedded_categories, select_categories, GenerateParams,
    Mode, Severity,
};
use wasm_bindgen::prelude::*;

/// Generate Little Snitch rules JSON from parameters.
///
/// # Arguments
/// * `mode` - "block" or "allow"
/// * `severity` - "minimal", "recommended", or "aggressive"
/// * `include` - Comma-separated list of category patterns to include
/// * `exclude` - Comma-separated list of category patterns to exclude
/// * `name` - Optional custom name for the ruleset
///
/// # Returns
/// JSON string of the generated rules, or an error message.
#[wasm_bindgen]
pub fn generate_rules(mode: &str, severity: &str, include: &str, exclude: &str, name: &str) -> Result<String, JsError> {
    let mode = Mode::from_str(mode).unwrap_or_default();
    let severity = Severity::from_str(severity).unwrap_or_default();

    let include: Vec<String> = if include.is_empty() {
        Vec::new()
    } else {
        include.split(',').map(|s| s.trim().to_string()).collect()
    };

    let exclude: Vec<String> = if exclude.is_empty() {
        Vec::new()
    } else {
        exclude.split(',').map(|s| s.trim().to_string()).collect()
    };

    let name = if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    };

    let params = GenerateParams {
        mode,
        severity,
        include,
        exclude,
        all: true, // In WASM mode, always include all categories matching criteria
        name,
    };

    let categories = load_embedded_categories().map_err(|e| JsError::new(&e))?;
    let selection = select_categories(&params, &categories);

    if selection.denied.is_empty() && selection.allowed.is_empty() {
        return Err(JsError::new(
            "No categories selected. Check your include/exclude patterns.",
        ));
    }

    let output = build_output(&params, &categories, &selection);
    serde_json::to_string_pretty(&output)
        .map_err(|e| JsError::new(&format!("JSON serialization error: {}", e)))
}

/// List all available categories with their metadata.
///
/// # Returns
/// JSON array of category objects with slug, name, description, severity, impact, and rule_count.
#[wasm_bindgen]
pub fn list_categories() -> Result<String, JsError> {
    let categories = load_embedded_categories().map_err(|e| JsError::new(&e))?;
    let info = get_category_info(&categories);
    serde_json::to_string(&info)
        .map_err(|e| JsError::new(&format!("JSON serialization error: {}", e)))
}

/// Get the version of the library.
#[wasm_bindgen]
pub fn get_version() -> String {
    crate::get_version().to_string()
}

/// Validate that category patterns match at least one category.
///
/// # Arguments
/// * `patterns` - Comma-separated list of patterns to validate
///
/// # Returns
/// JSON object with `valid` (bool) and `matched` (array of matched category slugs)
#[wasm_bindgen]
pub fn validate_patterns(patterns: &str) -> Result<String, JsError> {
    use crate::matches_pattern;

    let patterns: Vec<String> = if patterns.is_empty() {
        Vec::new()
    } else {
        patterns.split(',').map(|s| s.trim().to_string()).collect()
    };

    let categories = load_embedded_categories().map_err(|e| JsError::new(&e))?;

    let mut matched: Vec<String> = Vec::new();
    for (slug, _) in &categories {
        for pattern in &patterns {
            if matches_pattern(slug, pattern) {
                matched.push(slug.clone());
                break;
            }
        }
    }

    let result = serde_json::json!({
        "valid": !matched.is_empty() || patterns.is_empty(),
        "matched": matched
    });

    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("JSON serialization error: {}", e)))
}

/// Get detailed information about a specific category including all rules.
///
/// # Arguments
/// * `slug` - The category slug (e.g., "apple-telemetry")
///
/// # Returns
/// JSON object with full category details including domains and processes
#[wasm_bindgen]
pub fn get_category_details(slug: &str) -> Result<String, JsError> {
    let categories = load_embedded_categories().map_err(|e| JsError::new(&e))?;

    let category = categories
        .iter()
        .find(|(s, _)| s == slug)
        .map(|(_, c)| c)
        .ok_or_else(|| JsError::new(&format!("Category not found: {}", slug)))?;

    let mut domains: Vec<&str> = Vec::new();
    let mut processes: Vec<&str> = Vec::new();

    for rule in &category.rules {
        for domain in &rule.domains {
            domains.push(domain);
        }
        if let Some(process) = &rule.deny_process {
            processes.push(process);
        }
    }

    let result = serde_json::json!({
        "slug": slug,
        "name": category.name,
        "description": category.description,
        "severity": category.severity,
        "impact": category.impact,
        "domains": domains,
        "processes": processes,
        "rules": category.rules.iter().map(|r| {
            serde_json::json!({
                "notes": r.notes,
                "domains": r.domains,
                "process": r.deny_process
            })
        }).collect::<Vec<_>>()
    });

    serde_json::to_string_pretty(&result)
        .map_err(|e| JsError::new(&format!("JSON serialization error: {}", e)))
}
