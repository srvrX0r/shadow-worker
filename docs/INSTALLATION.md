# Installation Guide

Complete installation instructions for Shadow Worker.

## System Requirements

- **Python**: 3.10 or higher
- **Operating System**: Linux, macOS, or Windows
- **Memory**: Minimum 2GB RAM (4GB+ recommended for large scans)
- **Disk**: 500MB for installation + storage for scan data

## Installation Methods

### Method 1: pip (Recommended)

```bash
# Install from source
git clone https://github.com/srvrX0r/shadow-worker.git
cd shadow-worker
pip install -e .
```

### Method 2: Virtual Environment (Best Practice)

```bash
# Clone repository
git clone https://github.com/srvrX0r/shadow-worker.git
cd shadow-worker

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# Windows: venv\Scripts\activate

# Install Shadow Worker
pip install -e .
```

### Method 3: Docker

Build the image locally (or pull the published one from GHCR):

```bash
docker build -t shadow-worker:1.2.0 .
docker run --rm shadow-worker:1.2.0 --version
```

Run a scan with your configuration mounted read-only:

```bash
docker run --rm \
  -v "$(pwd)/shadow-config.yaml:/config/shadow-config.yaml:ro" \
  -v "$(pwd)/rules:/var/lib/shadow-worker/rules:ro" \
  -v shadow-data:/var/lib/shadow-worker/data \
  shadow-worker:1.2.0 scan https://your-app.example.com
```

Or use compose, which already runs the container as the non-root uid `10001`
with a read-only root filesystem:

```bash
docker compose run --rm shadow-worker status
docker compose run --rm shadow-worker scan ./project --type sast
```

Published images are `ghcr.io/srvrx0r/shadow-worker` (tagged by release
version and commit sha). The image healthchecks with `shadow --help`; set
`SHADOW_CONFIG` and `SHADOW_DATA_DIR` to relocate the configuration file and the
data volume.

## Optional Dependencies

### Development Tools

```bash
pip install -e ".[dev]"
```

Includes: pytest, mypy, ruff, black

### Web3 Security

```bash
pip install -e ".[web3]"
```

Includes: web3.py, slither-analyzer, mythril

### Mobile Security

```bash
pip install -e ".[mobile]"
```

Includes: frida, objection

## External Tool Installation

### Semgrep (Recommended)

```bash
pip install semgrep

# Verify installation
semgrep --version
```

### Bandit (Python Security)

```bash
pip install bandit

# Verify installation
bandit --version
```

### OWASP Noir (API Discovery)

```bash
# Using Homebrew (macOS)
brew install noir

# Using cargo (Rust)
cargo install noir

# From source
git clone https://github.com/owasp-noir/noir.git
cd noir && make install

# Verify installation
noir --version
```

### YARA (Malware Detection)

```bash
# Install yara-python
pip install yara-python

# For compiling custom rules, install YARA system package
# Ubuntu/Debian
sudo apt-get install yara

# macOS
brew install yara

# Verify installation
python -c "import yara; print('YARA OK')"
```

### Suricata (Network IDS)

```bash
# Ubuntu/Debian
sudo apt-get install suricata

# macOS
brew install suricata

# Configure and start
sudo suricata-update
sudo systemctl start suricata

# Verify installation
suricata --version
```

## Post-Installation Setup

### 1. Initialize Configuration

```bash
shadow init
```

This creates `shadow-config.yaml` with default settings.

### 2. Configure Authorized Targets

Edit `shadow-config.yaml`:

```yaml
# Add YOUR authorized targets
targets:
  hosts:
    - "192.168.1.100"  # Your server IP
  domains:
    - "yourdomain.com"  # Your domain
  networks:
    - "192.168.1.0/24"  # Your network

# Confirm authorization
authorization_confirmed: true
```

### 3. Set Up Detection Rules

```bash
# Create rules directories
mkdir -p rules/yara rules/suricata rules/custom

# Default rules are created automatically on first run
```

### 4. Configure Alerting (Optional)

```yaml
alerting:
  enabled: true
  slack_webhook: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  alert_on_severity: medium
```

### 5. Verify Installation

```bash
# Check status
shadow status

# Run a test scan on a local file
shadow scan ./README.md --type sast
```

## Troubleshooting

### Python Version Issues

```bash
# Check Python version
python --version

# Use specific Python version
python3.10 -m pip install -e .
```

### Permission Errors

```bash
# Use user installation
pip install --user -e .

# Or use virtual environment (recommended)
python -m venv venv
source venv/bin/activate
pip install -e .
```

### Missing System Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install python3-dev libffi-dev libssl-dev

# macOS
xcode-select --install
brew install openssl
```

### YARA Installation Issues

```bash
# Install build dependencies first
# Ubuntu/Debian
sudo apt-get install automake libtool make gcc pkg-config libssl-dev

# Then install yara-python
pip install yara-python
```

## Upgrading

```bash
# Pull latest changes
git pull origin main

# Reinstall
pip install -e .

# Verify version
shadow --version
```

## Uninstallation

```bash
# Uninstall package
pip uninstall shadow-worker

# Remove configuration and data (optional)
rm -rf shadow-config.yaml data/ rules/
```
