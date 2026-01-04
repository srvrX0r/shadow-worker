# Shadow Worker API Reference

Programmatic interface for integrating Shadow Worker into your applications.

## Core Classes

### ShadowEngine

Main orchestration engine for all security operations.

```python
from shadow_worker import ShadowEngine, ShadowConfig

# Initialize with configuration
config = ShadowConfig.load("shadow-config.yaml")
engine = ShadowEngine(config)

# Use as context manager
async with engine.run():
    result = await engine.scan(target)
```

#### Methods

##### `async scan(target, scan_type="full", options=None) -> ScanResult`

Execute a security scan against a target.

**Parameters**:
- `target` (str): URL, IP address, or path to scan
- `scan_type` (str): One of `"full"`, `"sast"`, `"dast"`, `"quick"`
- `options` (dict, optional): Additional scan options

**Returns**: `ScanResult` with findings

```python
result = await engine.scan("https://example.com", scan_type="dast")
print(f"Found {result.total_findings} vulnerabilities")
```

##### `async scan_repository(repo_path, branch="main", scan_type="sast") -> ScanResult`

Scan a local or remote repository.

```python
result = await engine.scan_repository("./my-project", branch="main")
```

##### `async continuous_monitor(targets, interval_seconds=3600, scan_type="quick") -> AsyncIterator[ScanResult]`

Continuously monitor targets at regular intervals.

```python
async for result in engine.continuous_monitor(["https://app1.com", "https://app2.com"]):
    process_results(result)
```

##### `async ingest_logs(logs, source="unknown") -> int`

Ingest logs into the SIEM pipeline.

```python
logs = [{"message": "Login failed", "user": "admin", "ip": "1.2.3.4"}]
count = await engine.ingest_logs(logs, source="auth-service")
```

##### `async detect_threats(data, filename="", scan_memory=False) -> list[dict]`

Scan data for threats using detection engines.

```python
with open("suspicious_file.bin", "rb") as f:
    threats = await engine.detect_threats(f.read(), filename="suspicious_file.bin")
```

##### `get_stats() -> dict`

Get current engine statistics.

```python
stats = engine.get_stats()
print(f"Total scans: {stats['total_scans']}")
```

##### `get_health() -> dict`

Get engine health status.

```python
health = engine.get_health()
if health['status'] == 'healthy':
    print("Engine is running normally")
```

---

### ShadowConfig

Configuration management for Shadow Worker.

```python
from shadow_worker import ShadowConfig

# Load from file
config = ShadowConfig.load("shadow-config.yaml")

# Load from environment/default locations
config = ShadowConfig.load_from_env()

# Create default configuration
config = ShadowConfig()

# Save configuration
config.save("shadow-config.yaml")
```

#### Attributes

- `name` (str): Configuration name
- `environment` (str): `"development"`, `"staging"`, or `"production"`
- `authorization_confirmed` (bool): Must be `True` to scan
- `targets` (TargetConfig): Authorized targets
- `siem` (SIEMConfig): SIEM settings
- `detection` (DetectionConfig): Threat detection settings
- `sast` (SASTConfig): Static analysis settings
- `dast` (DASTConfig): Dynamic analysis settings
- `alerting` (AlertingConfig): Alerting settings

---

### Scanner

Core vulnerability scanner.

```python
from shadow_worker.core.scanner import Scanner, ScanResult, Finding

scanner = Scanner(config)
result = await scanner.scan("https://target.com", scan_type="full")
```

#### Classes

##### `Finding`

Represents a security finding.

```python
@dataclass
class Finding:
    id: UUID
    title: str
    description: str
    severity: Severity  # info, low, medium, high, critical
    category: VulnCategory  # injection, xss, etc.
    target: str
    location: str
    line_number: int | None
    evidence: str
    remediation: str
    references: list[str]
    cwe_ids: list[int]
    cve_ids: list[str]
    scanner: str
    confidence: float
    timestamp: datetime
```

##### `ScanResult`

Result of a scan operation.

```python
@dataclass
class ScanResult:
    scan_id: UUID
    status: ScanStatus  # pending, running, completed, failed
    target: str
    scan_type: str
    findings: list[Finding]
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    errors: list[str]
```

---

### SIEMPipeline

Log aggregation and correlation.

```python
from shadow_worker.siem import SIEMPipeline

pipeline = SIEMPipeline(config.siem)
await pipeline.start()

# Ingest logs
await pipeline.ingest([
    {"message": "Login attempt", "user": "admin", "outcome": "failure"}
], source="auth-service")

# Query events
events = pipeline.get_events(
    start_time=datetime.now() - timedelta(hours=24),
    severity=EventSeverity.WARNING
)

# Get alerts
alerts = pipeline.get_alerts(unacknowledged_only=True)

await pipeline.stop()
```

#### Methods

##### `async ingest(logs, source="unknown") -> int`

Ingest logs into the pipeline.

##### `add_rule(rule: CorrelationRule) -> None`

Add a correlation rule.

##### `on_alert(callback: Callable) -> None`

Register callback for alerts.

##### `get_events(start_time, end_time, severity, category, limit) -> list[SecurityEvent]`

Query stored events.

##### `get_alerts(unacknowledged_only, limit) -> list[Alert]`

Get alerts with filters.

---

### ThreatDetector

YARA and custom rule detection.

```python
from shadow_worker.detection import ThreatDetector

detector = ThreatDetector(config.detection)
await detector.start()

# Scan data
threats = await detector.detect(data, filename="sample.exe")

# Scan file
threats = await detector.scan_file("/path/to/file")

# Scan directory
threats = await detector.scan_directory("/path/to/dir", recursive=True)

await detector.stop()
```

#### ThreatDetection

```python
@dataclass
class ThreatDetection:
    id: UUID
    timestamp: datetime
    threat_type: ThreatType  # malware, ransomware, trojan, etc.
    severity: ThreatSeverity
    confidence: float
    rule_name: str
    rule_id: str
    engine: str  # yara, suricata, custom
    filename: str
    filepath: str
    file_hash_sha256: str
    matched_strings: list[str]
    tags: list[str]
    description: str
    mitre_attack: list[str]
```

---

### NoirScanner

API endpoint discovery.

```python
from shadow_worker.scanners.noir import NoirScanner, discover_endpoints

scanner = NoirScanner()
result = await scanner.scan("./my-api", base_url="https://api.example.com")

for endpoint in result.endpoints:
    print(f"{endpoint.method} {endpoint.url}")

# Generate OpenAPI spec
spec = await scanner.generate_openapi_spec(result.endpoints)
```

---

### Alerter

Multi-channel alerting.

```python
from shadow_worker.alerting import Alerter, Alert

alerter = Alerter(config.alerting)

# Send alert
await alerter.send_alert(Alert(
    title="Critical Vulnerability Found",
    description="SQL injection in login endpoint",
    severity=Severity.CRITICAL,
    target="https://example.com/login"
))

# Send finding directly
await alerter.send_finding(finding)
```

---

## Enums

### Severity

```python
from shadow_worker.core.scanner import Severity

Severity.INFO
Severity.LOW
Severity.MEDIUM
Severity.HIGH
Severity.CRITICAL
```

### VulnCategory

```python
from shadow_worker.core.scanner import VulnCategory

VulnCategory.INJECTION      # SQL, command injection
VulnCategory.XSS            # Cross-site scripting
VulnCategory.BROKEN_AUTH    # Authentication issues
VulnCategory.SENSITIVE_DATA # Data exposure
VulnCategory.MISCONFIG      # Security misconfiguration
VulnCategory.CRYPTO         # Cryptographic failures
VulnCategory.SSRF           # Server-side request forgery
# ... and more
```

### ThreatType

```python
from shadow_worker.detection import ThreatType

ThreatType.MALWARE
ThreatType.RANSOMWARE
ThreatType.TROJAN
ThreatType.BACKDOOR
ThreatType.WEBSHELL
ThreatType.CRYPTOMINER
ThreatType.EXPLOIT
# ... and more
```

---

## Plugin System

Extend Shadow Worker with custom plugins.

```python
from shadow_worker.core.plugin import (
    Plugin,
    ScannerPlugin,
    DetectorPlugin,
    PluginMetadata,
    PluginType,
    PluginResult
)

class MyCustomScanner(ScannerPlugin):
    metadata = PluginMetadata(
        name="my-scanner",
        version="1.0.0",
        description="Custom vulnerability scanner",
        plugin_type=PluginType.SCANNER
    )

    async def initialize(self) -> None:
        # Setup code
        pass

    async def scan(self, target: str, options: dict) -> list[dict]:
        findings = []
        # Custom scanning logic
        return findings

# Register plugin
engine.plugin_manager.register(MyCustomScanner())
```

---

## Examples

### Complete Scan Workflow

```python
import asyncio
from shadow_worker import ShadowEngine, ShadowConfig

async def security_assessment(target: str):
    config = ShadowConfig.load("shadow-config.yaml")
    engine = ShadowEngine(config)

    async with engine.run():
        # Run comprehensive scan
        result = await engine.scan(target, scan_type="full")

        # Process findings by severity
        critical = [f for f in result.findings if f.severity.value == "critical"]
        high = [f for f in result.findings if f.severity.value == "high"]

        print(f"Scan complete: {result.total_findings} findings")
        print(f"  Critical: {len(critical)}")
        print(f"  High: {len(high)}")

        # Export results
        with open("report.json", "w") as f:
            import json
            json.dump([f.to_dict() for f in result.findings], f, indent=2)

        return result

asyncio.run(security_assessment("https://myapp.example.com"))
```

### SIEM Integration

```python
import asyncio
from shadow_worker.siem import SIEMPipeline, EventSeverity
from shadow_worker.core.config import SIEMConfig

async def monitor_logs():
    config = SIEMConfig(enabled=True, storage_path="./data/siem.db")
    pipeline = SIEMPipeline(config)

    # Register alert callback
    async def on_alert(alert):
        print(f"ALERT: {alert.title}")
        # Send to external system

    pipeline.on_alert(on_alert)

    await pipeline.start()

    # Ingest logs continuously
    while True:
        logs = await fetch_logs_from_source()
        await pipeline.ingest(logs, source="my-app")
        await asyncio.sleep(10)

asyncio.run(monitor_logs())
```

### Custom Detection Rules

```python
from shadow_worker.detection import ThreatDetector
from shadow_worker.core.config import DetectionConfig

async def custom_detection():
    config = DetectionConfig(
        enabled=True,
        yara_rules_path="./rules/yara",
        custom_rules_path="./rules/custom"
    )

    detector = ThreatDetector(config)
    await detector.start()

    # Scan uploaded files
    for filepath in uploaded_files:
        threats = await detector.scan_file(filepath)
        if threats:
            print(f"Threats in {filepath}:")
            for threat in threats:
                print(f"  - {threat.rule_name} ({threat.severity.value})")

    await detector.stop()
```
