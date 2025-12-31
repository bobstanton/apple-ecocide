# Apple Ecocide

Generate [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html) rules using human-readable categories.

- [Try the web app](https://bobstanton.github.io/apple-ecocide/)
- [Sample ruleset which blocks all but software updates](https://bobstanton.github.io/apple-ecocide/apple-ecocide.lsrules)

## Features

- **Category-based blocking** - Such as `apple-telemetry`,  `apple-icloud`,  `apple-ads`
- **Allowlist mode** - Block everything except explicitly permitted services
- **Auto-updating subscriptions** - Host rules on GitHub Pages, Little Snitch updates automatically
- **Wildcard patterns** - `*-telemetry` blocks all vendor telemetry at once
- **Severity levels** - Balance privacy against functionality (minimal → recommended → aggressive)

## Installation

### Prerequisites

```bash
# Install just (command runner)
cargo install just

# Install wasm-pack (for web app)
cargo install wasm-pack

# Install miniserve (for local dev server)
cargo install miniserve
```

### Quick Start

```bash
git clone https://github.com/bobstanton/apple-ecocide.git
cd apple-ecocide

just build    # Build CLI binary
just serve    # Build WASM and start local server
just all      # Build everything
```

### Manual Build

**CLI:**                    
```bash
cargo build --release
# Binary at ./target/release/apple-ecocide
```

**Web App:**
```bash
wasm-pack build --target web --out-dir web/pkg
miniserve web --index index.html -p 8080
```

The web app will be available at `http://localhost:8080`.

## Usage

### Web App

The web app provides:

**Interactive UI** - Visit the root URL to use the interactive form:
- Select categories with checkboxes
- Use quick-select buttons (All Telemetry, All Apple, etc.)
- Choose mode (block/allow)
- Click "Details" on any category to see the domains/processes it will block
- Preview generated JSON in real-time
- Download the generated rules

**Shareable URLs** - Selections are persisted in the URL query string:
- Bookmark URLs to save configurations
- Share URLs to distribute identical rulesets
- Revisit to regenerate rules after domain updates

Example URL:
```
https://bobstanton.github.io/apple-ecocide/?include=apple-telemetry,google-telemetry&mode=block&name=my-rules
```

### CLI

#### List available categories

```bash
# Brief listing
apple-ecocide --list

# Detailed listing with descriptions and impact
apple-ecocide --list --verbose
```

#### Block mode (default)

Block specific categories while allowing everything else:

```bash
# Block all categories with "recommended" severity (default)
apple-ecocide --output my-rules.lsrules

# Block all categories including "aggressive" ones
apple-ecocide --severity aggressive --output paranoid.lsrules

# Block only specific categories
apple-ecocide --include apple-telemetry google-ads --output minimal.lsrules

# Block all available categories
apple-ecocide --all --severity aggressive --output everything.lsrules
```

#### Allow mode

Block everything EXCEPT the specified categories. This generates both allow rules (for specified categories) and deny rules (for everything else):

```bash
# Block everything except App Store and Music
apple-ecocide -s aggressive --mode allow --include apple-appstore apple-music --output allow-media.lsrules

# Block everything except Software Updates
apple-ecocide -s aggressive --mode allow --include apple-appstore apple-software-updates
```

Note: In allow mode, `--severity aggressive` is typically recommended to include all categories in the deny list.

#### Options

| Option         | Short | Description                                                      |
|----------------|-------|------------------------------------------------------------------|
| `--mode`       | `-m`  | `block` (default) or `allow`                                     |
| `--include`    | `-i`  | Categories to include (supports wildcards, space-separated)      |
| `--exclude`    | `-x`  | Categories to exclude from blocking (supports wildcards)         |
| `--all`        | `-a`  | Include all categories                                           |
| `--severity`   | `-s`  | Maximum severity: `minimal`, `recommended` (default), `aggressive` |
| `--output`     | `-o`  | Output filename (default: `apple-ecocide.lsrules`)               |
| `--categories` | `-c`  | Path to categories directory                                     |
| `--list`       | `-l`  | List available categories                                        |
| `--verbose`    | `-v`  | Show detailed information                                        |
| `--name`       |       | Custom name for the ruleset                                      |

#### Wildcard Patterns

The `--include` and `--exclude` options support glob patterns:

- `*` matches any sequence of characters
- `?` matches any single character
- `[abc]` matches any character in the brackets

Examples:
```bash
# Block all telemetry categories
apple-ecocide --include '*-telemetry' -o telemetry.lsrules

# Block all Apple categories
apple-ecocide --include 'apple-*' -s aggressive -o apple.lsrules

# Block everything except App Store and software updates
apple-ecocide --all -s aggressive --exclude apple-appstore apple-software-updates -o strict.lsrules
```

## Severity Levels

Each category has a severity level indicating how aggressive the blocking is:

- **minimal**: Includes ads and telemetry tracking.
- **recommended**: Good balance of privacy and functionality. 
- **aggressive**: Maximum privacy, will block functionality such as iCloud.

## Category File Format

Categories are defined in TOML files in the `categories/` directory:

```toml
name = "Category Name"
description = "What this category blocks"
severity = "recommended"  # minimal, recommended, or aggressive

impact = """
- What will stop working
- What functionality is affected
- Any warnings or notes
"""

[[rules]]
notes = "Description of these domains"
domains = [
    "example.com",
    "api.example.com",
]

[[rules]]
notes = "Another group of domains"
domains = [
    "tracking.example.org",
]

[[rules]]
notes = "Block a specific process from all network access"
deny-process = "/System/Library/PrivateFrameworks/Example.framework/exampled"
```

### Rule Types

Each `[[rules]]` entry can contain:

- **`domains`** - List of domain names to block (or allow in allow mode)
- **`deny-process`** - Path to a macOS process/daemon to block from all network access

You can use either or both in a single rule entry. Process-based rules are useful for blocking system daemons that may connect to multiple or unknown domains.

## Adding New Categories

1. Create a new `.toml` file in the `categories/` directory
2. Follow the format above
3. Run `apple-ecocide --list` to verify it's detected
4. Rebuild your rules

## Examples

```bash
# Privacy-focused setup (block telemetry, keep essential services)
apple-ecocide --include \
    apple-telemetry \
    apple-siri \
    apple-intelligence \
    apple-ads \
    google-ads \
    google-telemetry \
    mozilla-telemetry \
    microsoft-telemetry \
    --output privacy.lsrules

# Block all telemetry categories using wildcards
apple-ecocide --include '*-telemetry' --output telemetry.lsrules

# Paranoid setup (block almost everything)
apple-ecocide --all --severity aggressive --output paranoid.lsrules

# Block everything except specific categories
apple-ecocide --all -s aggressive \
    --exclude apple-appstore apple-software-updates \
    --output strict.lsrules

# Allow only essential Apple services (block everything else)
apple-ecocide --mode allow \
    --include apple-appstore apple-software-updates \
    --severity aggressive \
    --output minimal-apple.lsrules
```

## Hosting Rules with GitHub Pages

An example ruleset is hosted at:

```
https://bobstanton.github.io/apple-ecocide/apple-ecocide.lsrules
```

This blocks everything except App Store and Software Updates. See [`.github/workflows/generate-rules.yml`](.github/workflows/generate-rules.yml) for the workflow that generates it.

### Hosting Custom Rules

Custom rulesets can be generated and hosted automatically using GitHub Actions and GitHub Pages.

#### Setup

1. Create a new GitHub repository
2. Copy [`.github/workflows/generate-rules.yml`](.github/workflows/generate-rules.yml)
3. Edit the `RULE_ARGS` environment variable
4. Enable GitHub Pages: **Settings > Pages > Source: GitHub Actions**
5. Push to trigger the workflow

The rules file will be available at `https://<username>.github.io/<repo>/apple-ecocide.lsrules`

#### Example Configurations

```bash
# Block everything except App Store and Software Updates
-s aggressive --mode allow --include apple-appstore apple-software-updates

# Block all telemetry from all vendors
--include *-telemetry

# Block everything except iCloud, App Store, and updates
-s aggressive --mode allow --include apple-icloud apple-appstore apple-software-updates
```

#### Subscribing in Little Snitch

To receive automatic updates when rules change:

1. Open Little Snitch Configuration
2. Go to **File > New Rule Group Subscription...**
3. Enter the GitHub Pages URL

Little Snitch will periodically check for updates and apply changes automatically.

## Dependencies

### Rust Crates

| Crate        | Version | Description                              |
|--------------|---------|------------------------------------------|
| anyhow       | 1       | Error handling                           |
| clap         | 4       | Command-line argument parsing (CLI only) |
| glob         | 0.3     | Pattern matching for wildcards           |
| rust-embed   | 8       | Embed files in binary at compile time    |
| serde        | 1       | Serialization/deserialization            |
| serde_json   | 1       | JSON support                             |
| toml         | 0.8     | TOML file parsing                        |
| walkdir      | 2       | Directory traversal (CLI only)           |
| wasm-bindgen | 0.2     | Rust/JavaScript interop (WASM only)      |

### Build Tools

| Tool      | Description                                |
|-----------|--------------------------------------------|
| cargo     | Rust package manager and build tool        |
| just      | Command runner for build tasks             |
| wasm-pack | Build tool for Rust-generated WebAssembly  |
| miniserve | Simple HTTP server for local development   |
