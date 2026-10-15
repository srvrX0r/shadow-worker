# Shadow Worker

**Comprehensive Defensive Security Operations Framework**

Shadow Worker is an enterprise-grade security platform for vulnerability scanning, SIEM operations, and threat detection. Designed for security professionals to protect their own infrastructure with automated scanning, real-time detection, and multi-channel alerting.

```
   ____  _               _                __        __         _
  / ___|| |__   __ _  __| | _____      __ \ \      / /__  _ __| | _____ _ __
  \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /  \ \ /\ / / _ \| '__| |/ / _ \ '__|
   ___) | | | | (_| | (_| | (_) \ V  V /    \ V  V / (_) | |  |   <  __/ |
  |____/|_| |_|\__,_|\__,_|\___/ \_/\_/      \_/\_/ \___/|_|  |_|\_\___|_|

  Defensive Security Operations Framework v1.1.0
```

## Features

### Vulnerability Scanning
- **SAST (Static Analysis)** - Code security scanning with Semgrep, Bandit, and custom patterns
- **DAST (Dynamic Analysis)** - Runtime web application testing for OWASP Top 10
- **API Discovery** - OWASP Noir integration for endpoint enumeration
- **Multi-language Support** - Python, JavaScript, TypeScript, Go, Rust, Java, PHP, Ruby

### SIEM Operations
- **Log Aggregation** - Multi-format parsing (JSON, Syslog, CEF, LEEF)
- **Event Correlation** - Real-time pattern detection and anomaly detection
- **Alert Management** - Severity-based routing with aggregation
- **Persistent Storage** - SQLite, PostgreSQL, or Elasticsearch backends

### Threat Detection
- **YARA Rules** - Signature-based malware detection
- **Suricata Integration** - Network-based intrusion detection
- **Custom Rules** - YAML-based detection patterns
- **File Scanning** - Binary analysis and hash checking

### Alerting & Reporting
- **Multi-Channel** - Slack, Discord, Email, PagerDuty, Webhooks
- **Alert Aggregation** - Prevents notification fatigue
- **SARIF Output** - IDE and CI/CD integration
- **JSON/HTML Reports** - Comprehensive findings documentation

## Quick Start

### Installation

```bash
git clone https://github.com/srvrX0r/shadow-worker.git
cd shadow-worker

python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

pip install -e .

# Optional extras
pip install -e ".[dev]"        # pytest, ruff
pip install -e ".[scanners]"   # semgrep, bandit
pip install -e ".[detection]"  # yara-python (needs libyara)
pip install -e ".[web3]"       # smart-contract analysis
pip install -e ".[mobile]"     # Frida
```

### Configuration

```bash
# Initialize configuration
shadow init

# Edit the configuration
vim shadow-config.yaml
```

**Important**: Before scanning, you must:
1. Add your authorized targets to the configuration
2. Set `authorization_confirmed: true`

### Basic Usage

```bash
# Run a security scan
shadow scan https://your-app.example.com

# Static analysis of source code
shadow scan ./your-project --type sast

# Quick reconnaissance
shadow scan 192.168.1.100 --type quick

# Discover API endpoints
shadow discover ./your-api-code

# Threat detection with YARA
shadow detect ./suspicious-files -r

# Show configuration status
shadow status
```

## CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `shadow init` | Initialize a new configuration file |
| `shadow scan <target>` | Run security scan against target |
| `shadow discover <path>` | Discover API endpoints from source code |
| `shadow detect <path>` | Scan files for threats with YARA |
| `shadow monitor` | Continuous monitoring mode |
| `shadow status` | Show configuration and status |

### Scan Types

| Type | Description |
|------|-------------|
| `full` | Complete SAST + DAST scan (default) |
| `sast` | Static analysis only |
| `dast` | Dynamic analysis only |
| `quick` | Fast reconnaissance and critical checks |

### Output Formats

| Format | Description |
|--------|-------------|
| `table` | Rich terminal table (default) |
| `json` | JSON output for automation |
| `sarif` | SARIF format for IDE integration |

## Architecture

```
shadow-worker/
├── src/shadow_worker/
│   ├── core/           # Engine, config, plugin system
│   ├── scanners/       # SAST, DAST, Noir, Quick scanners
│   ├── siem/           # Log aggregation and correlation
│   ├── detection/      # YARA, Suricata, custom rules
│   ├── alerting/       # Multi-channel notifications
│   └── cli.py          # Command-line interface
├── rules/
│   ├── yara/           # YARA detection rules
│   ├── suricata/       # Suricata IDS rules
│   └── custom/         # Custom YAML rules
└── data/               # SIEM database and logs
```

## Configuration

See `shadow-config.example.yaml` for full configuration options.

### Key Sections

```yaml
# Authorized targets (REQUIRED)
targets:
  hosts: ["192.168.1.100"]
  domains: ["example.com"]
  networks: ["10.0.0.0/8"]

# SIEM configuration
siem:
  enabled: true
  storage_backend: sqlite
  correlation_window_seconds: 300

# Alerting channels
alerting:
  slack_webhook: "https://hooks.slack.com/..."
  alert_on_severity: medium
```

## External Tools

Shadow Worker integrates with:

| Tool | Purpose | Installation |
|------|---------|--------------|
| [Semgrep](https://semgrep.dev) | Static analysis | `pip install semgrep` |
| [Bandit](https://bandit.readthedocs.io) | Python security | `pip install bandit` |
| [OWASP Noir](https://github.com/owasp-noir/noir) | API discovery | See Noir docs |
| [YARA](https://virustotal.github.io/yara/) | Malware detection | `pip install yara-python` |
| [Suricata](https://suricata.io) | Network IDS | System package |

## Programmatic Usage

```python
import asyncio
from shadow_worker import ShadowEngine, ShadowConfig

async def main():
    config = ShadowConfig.load("shadow-config.yaml")
    engine = ShadowEngine(config)

    async with engine.run():
        # Run a scan
        result = await engine.scan("https://myapp.example.com")

        for finding in result.findings:
            print(f"[{finding.severity.value}] {finding.title}")
            print(f"  Location: {finding.location}")
            print(f"  Remediation: {finding.remediation}")

asyncio.run(main())
```

## Security Notice

This tool is designed for **authorized security testing only**:

- Only scan systems you own or have explicit written permission to test
- Respect rate limits and rules of engagement
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

**Shadow Worker requires explicit authorization confirmation before scanning.**

## License

GNU Affero General Public License v3. See [LICENSE](LICENSE).

The package metadata, this README, and `LICENSE` all describe AGPL-3.0-only. Earlier drafts mentioned MIT and Apache; those claims were incorrect.

## CI/CD

GitHub Actions on `main` and pull requests:

- tests on Python 3.10, 3.11, and 3.12
- Ruff
- wheel build and `shadow --help` smoke
- container image build (no push)

Tag `v*` publishes a GitHub Release with the sdist and wheel, and pushes the image to `ghcr.io/srvrx0r/shadow-worker`.

```bash
docker build -t shadow-worker:1.1.0 .
docker run --rm shadow-worker:1.1.0 --version
```

The runtime image is non-root, does not shell out to a package manager, and healthchecks with `shadow --help`. Semgrep, Bandit, and YARA stay optional so the default image stays installable without native libraries. Mount a config and install the extras in a derived image when you need them.

## Contributing

Open a pull request against `main`. CI must be green. See [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/srvrX0r/shadow-worker/issues)
