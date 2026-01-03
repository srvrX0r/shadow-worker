# Shadow Worker CLI Guide

Complete reference for the Shadow Worker command-line interface.

## Getting Started

```bash
# Show help
shadow --help

# Show version
shadow --version

# Enable debug output
shadow --debug <command>
```

## Commands

### `shadow init`

Initialize a new Shadow Worker configuration file.

```bash
# Create default configuration
shadow init

# Specify output file
shadow init --output /path/to/config.yaml
```

**Output**: Creates `shadow-config.yaml` with default settings.

---

### `shadow scan`

Run security scans against targets.

```bash
shadow scan <TARGET> [OPTIONS]
```

**Arguments**:
- `TARGET`: URL, IP address, or file/directory path

**Options**:
| Option | Short | Description |
|--------|-------|-------------|
| `--type` | `-t` | Scan type: `full`, `sast`, `dast`, `quick` |
| `--output` | `-o` | Output file path |
| `--format` | `-f` | Output format: `table`, `json`, `sarif` |

**Examples**:

```bash
# Full scan of a web application
shadow scan https://myapp.example.com

# Static analysis of source code
shadow scan ./my-project --type sast

# Quick reconnaissance of a host
shadow scan 192.168.1.100 --type quick

# Export results to JSON
shadow scan https://myapp.example.com -o results.json -f json

# SARIF output for CI/CD
shadow scan ./code --type sast -f sarif -o results.sarif
```

**Scan Types**:

| Type | Description | Use Case |
|------|-------------|----------|
| `full` | SAST + DAST combined | Comprehensive security assessment |
| `sast` | Static analysis only | Source code review, CI/CD |
| `dast` | Dynamic analysis only | Running web applications |
| `quick` | Fast reconnaissance | Initial assessment, port scan |

---

### `shadow discover`

Discover API endpoints from source code using OWASP Noir.

```bash
shadow discover <PATH> [OPTIONS]
```

**Arguments**:
- `PATH`: Directory containing source code

**Options**:
| Option | Short | Description |
|--------|-------|-------------|
| `--base-url` | `-u` | Base URL for endpoint construction |
| `--output` | `-o` | Output file path |
| `--format` | `-f` | Output format: `table`, `json`, `openapi` |

**Examples**:

```bash
# Discover endpoints in a project
shadow discover ./my-api

# With base URL
shadow discover ./my-api --base-url https://api.example.com

# Export as OpenAPI specification
shadow discover ./my-api --format openapi -o openapi.json

# JSON output for processing
shadow discover ./my-api -f json
```

**Supported Frameworks**:
- Python: Flask, FastAPI, Django, Tornado
- JavaScript: Express, Koa, Fastify, Hapi
- Go: Gin, Echo, Fiber
- Ruby: Rails, Sinatra
- Java: Spring, JAX-RS
- PHP: Laravel, Symfony

---

### `shadow detect`

Scan files for threats using YARA rules and custom signatures.

```bash
shadow detect <PATH> [OPTIONS]
```

**Arguments**:
- `PATH`: File or directory to scan

**Options**:
| Option | Short | Description |
|--------|-------|-------------|
| `--recursive` | `-r` | Scan directories recursively |
| `--output` | `-o` | Output file path |

**Examples**:

```bash
# Scan a single file
shadow detect ./suspicious-file.exe

# Recursive directory scan
shadow detect ./uploads -r

# Export results
shadow detect ./files -r -o threats.json
```

**Detection Capabilities**:
- Malware signatures (YARA)
- Webshells
- Cryptocurrency miners
- Ransomware indicators
- Reverse shells
- Credential dumpers

---

### `shadow monitor`

Continuous monitoring mode for ongoing security assessment.

```bash
shadow monitor [OPTIONS]
```

**Options**:
| Option | Short | Description |
|--------|-------|-------------|
| `--interval` | `-i` | Scan interval in seconds (default: 3600) |

**Examples**:

```bash
# Start monitoring with default interval (1 hour)
shadow monitor

# Custom interval (every 15 minutes)
shadow monitor --interval 900

# Stop with Ctrl+C
```

**Requirements**:
- Configuration must have `authorization_confirmed: true`
- Targets must be configured in `targets:` section

---

### `shadow status`

Display current configuration and system status.

```bash
shadow status
```

**Output**:
```
Shadow Worker Configuration
├── Targets
│   ├── Hosts: 3
│   ├── Networks: 2
│   ├── Domains: 1
│   └── Authorized: ✓
├── SIEM
│   ├── Enabled: True
│   └── Storage: sqlite
├── Detection
│   ├── Enabled: True
│   ├── YARA: ./rules/yara
│   └── Suricata: False
├── Scanners
│   ├── SAST: True
│   ├── DAST: True
│   └── Web3: False
└── Alerting
    ├── Enabled: True
    ├── Slack: ✓
    ├── Discord: ✗
    └── Email: ✗
```

---

## Global Options

Available for all commands:

| Option | Short | Description |
|--------|-------|-------------|
| `--config` | `-c` | Path to configuration file |
| `--debug` | | Enable debug output |
| `--help` | | Show help message |
| `--version` | | Show version |

**Examples**:

```bash
# Use custom configuration
shadow --config /path/to/config.yaml scan https://example.com

# Enable debug mode
shadow --debug scan ./code --type sast
```

---

## Output Formats

### Table (Default)

Rich terminal output with colored severity indicators:

```
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Title                       ┃ Location       ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ CRITICAL │ SQL Injection               │ api/users.py   │
│ HIGH     │ Hardcoded Secret            │ config.py      │
│ MEDIUM   │ Missing HSTS Header         │ /              │
└──────────┴─────────────────────────────┴────────────────┘
```

### JSON

Machine-readable JSON output:

```bash
shadow scan ./code --type sast -f json -o results.json
```

```json
{
  "scan_id": "uuid",
  "target": "./code",
  "status": "completed",
  "findings": [...],
  "summary": {
    "total": 15,
    "critical": 2,
    "high": 5,
    "medium": 8
  }
}
```

### SARIF

Static Analysis Results Interchange Format for IDE/CI integration:

```bash
shadow scan ./code --type sast -f sarif -o results.sarif
```

Compatible with:
- GitHub Code Scanning
- VS Code SARIF Viewer
- Azure DevOps

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no critical findings |
| 1 | Error or critical findings found |
| 2 | Configuration error |
| 130 | Interrupted (Ctrl+C) |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SHADOW_CONFIG` | Default configuration file path |
| `SHADOW_DATA_DIR` | Data directory for SIEM/logs |
| `SHADOW_LOG_LEVEL` | Logging level (DEBUG, INFO, etc.) |

---

## Automation Examples

### CI/CD Pipeline (GitHub Actions)

```yaml
- name: Security Scan
  run: |
    pip install shadow-worker
    shadow scan . --type sast -f sarif -o results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Scheduled Scans (Cron)

```bash
# Run full scan daily at 2 AM
0 2 * * * /path/to/shadow scan https://myapp.com -o /var/log/shadow/$(date +\%Y\%m\%d).json -f json
```

### Continuous Monitoring Script

```bash
#!/bin/bash
shadow monitor --interval 1800 2>&1 | tee /var/log/shadow/monitor.log
```
