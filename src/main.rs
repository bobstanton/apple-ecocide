#![cfg(feature = "cli")]

use anyhow::{Context, Result};
use apple_ecocide::{
    build_output, load_embedded_categories, select_categories, Category, CategorySelection,
    GenerateParams, Mode, Severity,
};
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{ArgAction, Parser, ValueEnum};
use std::path::{Path, PathBuf};
use std::{env, fs};
use walkdir::WalkDir;

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default())
    .valid(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD));

#[derive(Parser, Debug)]
#[command(name = "apple-ecocide")]
#[command(version, about, long_about = None)]
#[command(styles = STYLES)]
#[command(after_help = "\
\x1b[1;32mExamples:\x1b[0m
    Block all telemetry at recommended severity:
    \x1b[1;36m$ apple-ecocide --output my-rules.lsrules\x1b[0m

    Block only specific categories:
    \x1b[1;36m$ apple-ecocide --include apple-telemetry google-telemetry -o rules.lsrules\x1b[0m

    Block all telemetry categories using wildcards:
    \x1b[1;36m$ apple-ecocide --include '*-telemetry' -o telemetry.lsrules\x1b[0m

    Block everything including aggressive categories:
    \x1b[1;36m$ apple-ecocide --all --severity aggressive -o strict.lsrules\x1b[0m

    Block everything except specific categories:
    \x1b[1;36m$ apple-ecocide --all -s aggressive --exclude apple-appstore apple-software-updates -o rules.lsrules\x1b[0m

    Allow mode (allow specified, deny everything else):
    \x1b[1;36m$ apple-ecocide --mode allow --include apple-appstore apple-software-updates -o rules.lsrules\x1b[0m

    List all available categories:
    \x1b[1;36m$ apple-ecocide --list --verbose\x1b[0m

\x1b[1;32mWildcards:\x1b[0m
    The \x1b[1;36m--include\x1b[0m option supports glob patterns:
      \x1b[1;36m*\x1b[0m           matches any sequence of characters
      \x1b[1;36m?\x1b[0m           matches any single character
      \x1b[1;36m[abc]\x1b[0m       matches any character in the brackets

    Pattern examples:
      \x1b[1;36m'*-telemetry'\x1b[0m     all telemetry categories
      \x1b[1;36m'apple-*'\x1b[0m         all Apple categories
      \x1b[1;36m'google-*'\x1b[0m        all Google categories

\x1b[1;32mCategories:\x1b[0m
    Categories are embedded in the binary by default. Use \x1b[1;36m--categories\x1b[0m to
    override with a custom directory of TOML files.
")]
struct Args {
    /// Mode: 'block' blocks selected categories, 'allow' blocks everything except selected
    #[arg(short, long, value_enum, default_value_t = CliMode::Block)]
    mode: CliMode,

    /// Categories to include (supports wildcards: '*-telemetry', 'apple-*')
    #[arg(short, long, num_args = 1.., value_name = "PATTERN")]
    include: Option<Vec<String>>,

    /// Categories to exclude from blocking (supports wildcards)
    #[arg(short = 'x', long, num_args = 1.., value_name = "PATTERN")]
    exclude: Option<Vec<String>>,

    /// Include all categories up to the severity threshold
    #[arg(short, long, action = ArgAction::SetTrue)]
    all: bool,

    /// Maximum severity level to include (minimal < recommended < aggressive)
    #[arg(short, long, value_enum, default_value_t = CliSeverity::Recommended)]
    severity: CliSeverity,

    /// Output file path
    #[arg(short, long, default_value = "apple-ecocide.lsrules", value_name = "FILE")]
    output: PathBuf,

    /// Path to categories directory (overrides embedded categories)
    #[arg(short, long, value_name = "DIR")]
    categories: Option<PathBuf>,

    /// List available categories and exit
    #[arg(short, long, action = ArgAction::SetTrue)]
    list: bool,

    /// Show detailed descriptions and impact information
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,

    /// Custom name for the ruleset in the output file
    #[arg(long, value_name = "NAME")]
    name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
enum CliMode {
    /// Block specified categories (or all with --all)
    #[default]
    Block,
    /// Allow only specified categories, block everything else
    Allow,
}

impl From<CliMode> for Mode {
    fn from(m: CliMode) -> Self {
        match m {
            CliMode::Block => Mode::Block,
            CliMode::Allow => Mode::Allow,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, ValueEnum)]
enum CliSeverity {
    /// Minimal blocking - only the most egregious tracking
    Minimal,
    /// Recommended blocking - good balance of privacy and functionality
    #[default]
    Recommended,
    /// Aggressive blocking - maximum privacy, may break usability
    Aggressive,
}

impl From<CliSeverity> for Severity {
    fn from(s: CliSeverity) -> Self {
        match s {
            CliSeverity::Minimal => Severity::Minimal,
            CliSeverity::Recommended => Severity::Recommended,
            CliSeverity::Aggressive => Severity::Aggressive,
        }
    }
}

/// Source of categories (embedded or filesystem)
enum CategorySource {
    Embedded,
    Filesystem(PathBuf),
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (categories, source) = load_categories(args.categories.as_deref())?;

    if args.list {
        list_categories(&categories, &source, args.verbose);
        return Ok(());
    }

    let params = GenerateParams {
        mode: args.mode.into(),
        severity: args.severity.into(),
        include: args.include.clone().unwrap_or_default(),
        exclude: args.exclude.clone().unwrap_or_default(),
        all: args.all,
        name: args.name.clone(),
    };

    let selection = select_categories(&params, &categories);

    if selection.denied.is_empty() && selection.allowed.is_empty() {
        eprintln!("No categories selected. Use --include or --all to select categories.");
        std::process::exit(1);
    }

    let output = build_output(&params, &categories, &selection);
    let output_path = resolve_output_path(&args.output)?;
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&output_path, &json)?;

    print_summary(&output_path, &output, &selection);

    Ok(())
}

fn print_summary(output_path: &Path, output: &apple_ecocide::LsRulesOutput, selection: &CategorySelection) {
    let total_categories = selection.denied.len() + selection.allowed.len();
    if selection.allowed.is_empty() {
        println!(
            "Generated {} with {} rules ({} deny) from {} categories",
            output_path.display(),
            output.rules.len(),
            output.rules.len(),
            total_categories
        );
    } else {
        let allow_count = output.rules.iter().filter(|r| r.action == "allow").count();
        let deny_count = output.rules.len() - allow_count;
        println!(
            "Generated {} with {} rules ({} allow, {} deny) from {} categories",
            output_path.display(),
            output.rules.len(),
            allow_count,
            deny_count,
            total_categories
        );
    }
}

fn resolve_output_path(output: &Path) -> Result<PathBuf> {
    if output.is_relative() && output.components().count() == 1 {
        Ok(env::current_dir()?.join(output))
    } else {
        Ok(output.to_path_buf())
    }
}

fn find_categories_dir(path: &Path) -> Option<PathBuf> {
    [
        Some(path.to_path_buf()),
        env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join(path))),
        env::current_dir().ok().map(|cwd| cwd.join(path)),
    ]
    .into_iter()
    .flatten()
    .find(|p| p.is_dir())
}

fn load_categories(custom_path: Option<&Path>) -> Result<(Vec<(String, Category)>, CategorySource)> {
    if let Some(path) = custom_path {
        if let Some(dir) = find_categories_dir(path) {
            let categories = load_categories_from_dir(&dir)?;
            return Ok((categories, CategorySource::Filesystem(dir)));
        }
        anyhow::bail!(
            "Categories directory not found: {}. Try specifying a valid --categories <path>",
            path.display()
        );
    }

    let categories = load_embedded_categories().map_err(|e| anyhow::anyhow!("Failed to load categories: {}", e))?;
    
    Ok((categories, CategorySource::Embedded))
}

fn load_categories_from_dir(path: &Path) -> Result<Vec<(String, Category)>> {
    let mut categories = Vec::new();

    for entry in WalkDir::new(path)
        .max_depth(1)
        .into_iter()
        .filter_map(Result::ok)
    {
        let file_path = entry.path();
        if file_path.extension().is_some_and(|ext| ext == "toml") {
            let content = fs::read_to_string(file_path)
                .context(format!("Failed to read: {}", file_path.display()))?;
            let category: Category = toml::from_str(&content)
                .context(format!("Failed to parse: {}", file_path.display()))?;
            let slug = file_path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            categories.push((slug, category));
        }
    }

    categories.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(categories)
}

fn list_categories(categories: &[(String, Category)], source: &CategorySource, verbose: bool) {
    match source {
        CategorySource::Embedded => println!("Available categories (embedded):\n"),
        CategorySource::Filesystem(path) => {
            println!("Available categories (from {}):\n", path.display())
        }
    }

    for (slug, cat) in categories {
        if verbose {
            println!("  {} ({})", slug, cat.severity);
            println!("    Name: {}", cat.name);
            println!("    Description: {}", cat.description);
            println!(
                "    Impact: {}",
                cat.impact.trim().replace('\n', "\n            ")
            );
            println!();
        } else {
            println!("  {slug:30} [{:11}] {}", cat.severity, cat.name);
        }
    }

    if !verbose {
        println!("\nUse --verbose for detailed descriptions and impact information.");
    }
}

