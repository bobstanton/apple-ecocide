//! Core library for generating Little Snitch privacy rules.
//!
//! This module contains the platform-agnostic logic for loading categories,
//! selecting rules, and building the output JSON.

use glob::Pattern;
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[derive(Embed)]
#[folder = "categories/"]
#[include = "*.toml"]
pub struct EmbeddedCategories;

/// Mode for rule generation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Block specified categories (or all with --all)
    #[default]
    Block,
    /// Allow only specified categories, block everything else
    Allow,
}

impl Mode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "block" => Some(Mode::Block),
            "allow" => Some(Mode::Allow),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Block => "block",
            Mode::Allow => "allow",
        }
    }
}

/// Severity level for categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Minimal blocking - only the most egregious tracking
    Minimal,
    /// Recommended blocking - good balance of privacy and functionality
    #[default]
    Recommended,
    /// Aggressive blocking - maximum privacy, may break usability
    Aggressive,
}

impl Severity {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "minimal" => Some(Severity::Minimal),
            "recommended" => Some(Severity::Recommended),
            "aggressive" => Some(Severity::Aggressive),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Minimal => "minimal",
            Severity::Recommended => "recommended",
            Severity::Aggressive => "aggressive",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A category file containing rules for a specific service/feature
#[derive(Debug, Deserialize, Clone)]
pub struct Category {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub impact: String,
    pub rules: Vec<CategoryRule>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CategoryRule {
    pub notes: String,
    #[serde(default)]
    pub domains: Vec<String>,
    /// Process path to block from all network access
    #[serde(rename = "deny-process")]
    pub deny_process: Option<String>,
}

/// Output format for Little Snitch rules
#[derive(Debug, Serialize)]
pub struct LsRulesOutput {
    pub name: String,
    pub description: String,
    pub rules: Vec<LsRule>,
}

#[derive(Debug, Serialize)]
pub struct LsRule {
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<&'static str>,
    pub process: String,
    #[serde(rename = "remote-domains", skip_serializing_if = "Vec::is_empty")]
    pub remote_domains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    pub notes: String,
}

/// Selection result containing both denied and allowed categories
#[derive(Default, Debug)]
pub struct CategorySelection {
    pub denied: HashSet<String>,
    pub allowed: HashSet<String>,
}

/// Parameters for generating rules
#[derive(Debug, Default)]
pub struct GenerateParams {
    pub mode: Mode,
    pub severity: Severity,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub all: bool,
    pub name: Option<String>,
}

/// Category metadata for listing (used by UI)
#[derive(Debug, Serialize)]
pub struct CategoryInfo {
    pub slug: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub impact: String,
    pub rule_count: usize,
}

/// Load embedded categories from the binary
pub fn load_embedded_categories() -> Result<Vec<(String, Category)>, String> {
    let mut categories = Vec::new();

    for name in EmbeddedCategories::iter().filter(|n| n.ends_with(".toml")) {
        let content = EmbeddedCategories::get(&name)
            .ok_or_else(|| format!("Failed to load embedded category: {}", name))?;
        let content_str = std::str::from_utf8(content.data.as_ref())
            .map_err(|_| format!("Invalid UTF-8 in category: {}", name))?;
        let category: Category = toml::from_str(content_str)
            .map_err(|e| format!("Failed to parse category {}: {}", name, e))?;
        let slug = name.trim_end_matches(".toml").to_string();
        categories.push((slug, category));
    }

    categories.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(categories)
}

/// Get category metadata for UI display
pub fn get_category_info(categories: &[(String, Category)]) -> Vec<CategoryInfo> {
    categories
        .iter()
        .map(|(slug, cat)| CategoryInfo {
            slug: slug.clone(),
            name: cat.name.clone(),
            description: cat.description.clone(),
            severity: cat.severity,
            impact: cat.impact.clone(),
            rule_count: cat.rules.len(),
        })
        .collect()
}

/// Check if a slug matches a single pattern (supports glob wildcards)
pub fn matches_pattern(slug: &str, pattern: &str) -> bool {
    if pattern.contains(['*', '?', '[']) {
        Pattern::new(pattern).is_ok_and(|p| p.matches(slug))
    } else {
        pattern == slug
    }
}

/// Check if a slug matches any of the given patterns
pub fn matches_any_pattern(slug: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| matches_pattern(slug, p))
}

/// Select categories based on parameters
pub fn select_categories(params: &GenerateParams, categories: &[(String, Category)]) -> CategorySelection {
    let exclude_patterns = &params.exclude;
    let include_patterns = &params.include;

    let within_severity = |cat: &Category| cat.severity <= params.severity;
    let is_excluded =
        |slug: &str| !exclude_patterns.is_empty() && matches_any_pattern(slug, exclude_patterns);

    match (&params.mode, !include_patterns.is_empty(), params.all) {
        // Block mode with --all or default (no includes): deny all within severity (minus excludes)
        (Mode::Block, false, _) | (Mode::Block, _, true) => CategorySelection {
            denied: categories
                .iter()
                .filter(|(slug, cat)| within_severity(cat) && !is_excluded(slug))
                .map(|(slug, _)| slug.clone())
                .collect(),
            ..Default::default()
        },

        // Block mode with --include: deny matching categories within severity
        (Mode::Block, true, false) => {
            let mut selection = CategorySelection::default();
            for (slug, cat) in categories {
                if matches_any_pattern(slug, include_patterns) && !is_excluded(slug) {
                    if within_severity(cat) {
                        selection.denied.insert(slug.clone());
                    }
                    // In WASM we skip the warning - no stderr
                }
            }
            selection
        }

        // Allow mode: allow specified, deny everything else
        (Mode::Allow, _, _) => {
            let mut selection = CategorySelection::default();
            for (slug, cat) in categories {
                if !within_severity(cat) {
                    continue;
                }

                if matches_any_pattern(slug, include_patterns) {
                    selection.allowed.insert(slug.clone());
                } else if !is_excluded(slug) {
                    selection.denied.insert(slug.clone());
                }
            }
            selection
        }
    }
}

/// Build the output structure
pub fn build_output(params: &GenerateParams, categories: &[(String, Category)], selection: &CategorySelection) -> LsRulesOutput {
    let mut rules = Vec::new();

    // 1. Process-based deny rules first (high priority - blocks specific processes entirely)
    for (slug, category) in categories
        .iter()
        .filter(|(s, _)| selection.denied.contains(s))
    {
        for rule in &category.rules {
            if let Some(process) = &rule.deny_process {
                rules.push(LsRule {
                    action: "deny",
                    priority: Some("high"),
                    process: process.clone(),
                    remote_domains: Vec::new(),
                    remote: Some("any"),
                    protocol: Some("any"),
                    disabled: None,
                    notes: format!("[{}] {}", slug, rule.notes),
                });
            }
        }
    }

    // 2. Domain-based deny rules (blocks domains for any process)
    for (slug, category) in categories
        .iter()
        .filter(|(s, _)| selection.denied.contains(s))
    {
        for rule in &category.rules {
            if !rule.domains.is_empty() {
                rules.push(LsRule {
                    action: "deny",
                    priority: None,
                    process: "any".into(),
                    remote_domains: rule.domains.clone(),
                    remote: None,
                    protocol: None,
                    disabled: None,
                    notes: format!("[{}] {}", slug, rule.notes),
                });
            }
        }
    }

    // 3. Allow rules last (regular priority - only applies if no high-priority deny matched)
    for (slug, category) in categories
        .iter()
        .filter(|(s, _)| selection.allowed.contains(s))
    {
        for rule in &category.rules {
            if !rule.domains.is_empty() {
                rules.push(LsRule {
                    action: "allow",
                    priority: None,
                    process: "any".into(),
                    remote_domains: rule.domains.clone(),
                    remote: None,
                    protocol: None,
                    disabled: Some(false),
                    notes: format!("[{}] {}", slug, rule.notes),
                });
            }
        }
    }

    let description = build_description(params, selection);

    LsRulesOutput {
        name: params
            .name
            .clone()
            .unwrap_or_else(|| "Apple Ecocide".into()),
        description,
        rules,
    }
}

fn build_description(params: &GenerateParams, selection: &CategorySelection) -> String {
    let mode_str = params.mode.as_str();

    let mut denied: Vec<_> = selection.denied.iter().map(String::as_str).collect();
    denied.sort();
    let mut allowed: Vec<_> = selection.allowed.iter().map(String::as_str).collect();
    allowed.sort();

    if allowed.is_empty() {
        format!(
            "Generated by apple-ecocide v{}. Mode: {}. Severity: {}. Denied ({}): {}",
            env!("CARGO_PKG_VERSION"),
            mode_str,
            params.severity,
            denied.len(),
            denied.join(", ")
        )
    } else {
        format!(
            "Generated by apple-ecocide v{}. Mode: {}. Severity: {}. Allowed ({}): {}. Denied ({}): {}",
            env!("CARGO_PKG_VERSION"),
            mode_str,
            params.severity,
            allowed.len(),
            allowed.join(", "),
            denied.len(),
            denied.join(", ")
        )
    }
}

/// Generate rules JSON string from parameters
pub fn generate_rules_json(params: &GenerateParams) -> Result<String, String> {
    let categories = load_embedded_categories()?;
    let selection = select_categories(params, &categories);

    if selection.denied.is_empty() && selection.allowed.is_empty() {
        return Err("No categories selected. Use include patterns or enable 'all'.".to_string());
    }

    let output = build_output(params, &categories, &selection);
    serde_json::to_string_pretty(&output).map_err(|e| format!("JSON serialization error: {}", e))
}

/// Get version string
pub fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
