# Vulnfy
**Vulnfy** is a lightweight, cross-platform dependency and container vulnerability scanner written in Python. It automatically detects project configuration/lock files across multiple languages and ecosystems, queries the OSV (Open Source Vulnerabilities) API, and generates a structured JSON vulnerability report.

---

## Telegram Showcase
![telegramapi](https://github.com/wxwreak/vulnfy/blob/main/telegramapi.png)

---

## Features
- **Multi-Ecosystem Support:** Scans dependencies for Python, Node.js, Go, PHP, Rust, and container base images.
- **Batch OSV API Integration:** Efficiently checks packages in bulk using the OSV batch query API.
- **Smart Notifications:** Automatically sends alerts to Discord or Telegram **only when vulnerabilities match or exceed your configured threshold**, completely eliminating spam when your codebase is clean.
- **CI/CD Ready & Threshold Control:** Use `--fail-on <level>` to customize when the build fails (`low`, `medium`, `high`, `critical`).
- **Vulnerability Suppression (`.vulnignore`):** Easily ignore known or unfixable vulnerabilities directly from your project's root directory to prevent CI blockage and **alert fatigue**.
- **Automatic Dependency Resolution:** Automatically installs missing requirements (`requests`, `colorama`, `PyYAML`) on first run.
- **Structured Output:** Exports all discovered vulnerabilities and associated CVEs into a clean JSON report.

## Supports
| Lang          | File          |
| ------------- |:-------------:|
| Python        | requirements.txt, pyproject.toml |
| NPM           | package.json, package-lock.json  |
| Go            | go.mod      |
| PHP           | composer.lock |
| Rust          | Cargo.lock, Cargo.toml |
| Docker        | Dockerfile, docker-compose.yml | 

## Report example
This is a Python example, but some results do not have an assigned CVE.
```json
{
    "ecosystem": "PyPI",
    "package": "jinja2",
    "vulnerability_id": "PYSEC-2026-1474",
    "cve": "CVE-2024-34064",
    "severity": "CVSS:3.1",
    "published": "2026-07-07",
    "description": "Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter"
},
```

## Configuration (`vulnfy.yaml`)
Create a `vulnfy.yaml` file in the root directory to enable notifications:
```yaml
notifications:
  discord:
    enabled: true   # Set to true to enable Discord alerts
  telegram:
    enabled: false  # Set to true to enable Telegram alerts
```

## Environment Variables (`.env`)
For security reasons, API tokens and webhooks are loaded from environment variables. Copy `.env.example` to `.env` and fill in your credentials:
```env
# Can be used in Github Actions
# --- Discord ---
DISCORD_WEBHOOK_URL=
# --- Telegram ---
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

## Suppressing Vulnerabilities (`.vulnignore`)
If you have vulnerabilities that you are aware of and cannot fix immediately (or want to suppress false positives), create a `.vulnignore` file in your **project's root directory.**

Add vulnerability IDs or CVEs (one per line):
```plaintext
# .vulnignore example
PYSEC-2026-1474
CVE-2024-34064
```
Ignored vulnerabilities will still appear in the raw JSON report if found, but they **will not** trigger CI failures or send notifications.

## CI/CD  Integration (Github Actions)
1. Create a `vulnfy.yaml` file in your repository root (as shown above).
2. Add your tokens to your repository **Settings -> Secret and variables -> Actions** (`DISCORD_WEBHOOK_URL`, etc..).
3. Create a workflow file in your project at `.github/workflows/scan.yaml`:
```yml
name: Vulnfy Security Scan

on:
  push:
    branches: [ main ]
  workflow_dispatch:

jobs:
  vulnfy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Vulnfy
        run: pip install git+https://github.com/wxwreak/vulnfy.git

      - name: Run Vulnfy Scanner
        env:
          DISCORD_WEBHOOK_URL: ${{ secrets.DISCORD_WEBHOOK_URL }}
          TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}
          TELEGRAM_CHAT_ID: ${{ secrets.TELEGRAM_CHAT_ID }}
        run: vulnfy --fail-on high
```

## Installation
```bash
curl -sSL https://github.com/wxwreak/vulnfy/blob/main/vulnfy_setup.sh | bash
```

## Usage
| Command | Description |
| :--- | :--- |
| `vulnfy` | Scans the current directory (default) |
| `vulnfy --path <dir>` (Or `-p`) | Scans a custom directory |
| `vulnfy --output <filename>` (Or `-o`) | Custom report file (Only json) |
| `vulnfy --fail-on <level>` | Minimum severity to fail CI (`low`, `medium`, `high`, `critical`) |
| `vulnfy --format <ext>`    | Formats (`json`, `markdown`, `html`, `pdf`, `csv`, `yaml`) Default is json |
| `vulnfy --no-cache`        | Disable Disable pycache |