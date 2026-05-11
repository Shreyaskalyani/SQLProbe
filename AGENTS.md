# SQL Injection Assessment Framework - Usage Guide

## Running the Framework

### Install Dependencies
```bash
pip install -r requirements.txt
```

### CLI Usage
```bash
# Basic scan
python -m sqlprobe -u "http://example.com/page.php?id=1"

# Scan with depth and concurrency
python -m sqlprobe -u "http://example.com" -d 3 -c 20

# Scan with proxy (for Burp Suite / OWASP ZAP)
python -m sqlprobe -u "http://example.com" -p "http://localhost:8080"

# Generate json report
python -m sqlprobe -u "http://example.com" -o results --format json

# Load previous session
python -m sqlprobe --load-session session.json
```

### Python API Usage
```python
import asyncio
from sqlprobe.engine import AssessmentEngine

async def scan():
    engine = AssessmentEngine(
        target="http://example.com/page.php?id=1",
        depth=2,
        concurrency=10,
    )
    results = await engine.run()
    return results

asyncio.run(scan())
```

## Testing Commands

Run basic syntax check:
```bash
python -m py_compile sqlprobe/__init__.py
```

List all modules:
```bash
python -c "import sqlprobe; print(sqlprobe.__version__)"
```

Run quick_scan tests:
```bash
python -m unittest test_quick_scan -v
```

## Key Design Principles

1. **Detection Only**: This framework detects SQL injection vulnerabilities but does NOT exploit them or extract data
2. **Authorization Required**: Always ensure you have explicit permission before testing any target
3. **Safety Controls**: Domain whitelist enforcement and rate limiting are built-in
4. **Modular Architecture**: Each module can be extended via the plugin system

## Module Structure

- `engine/` - Async HTTP engine and main assessment orchestration
- `payloads/` - SQL injection payload generation and mutation
- `detection/` - Vulnerability detection and response analysis
- `crawler/` - Smart web crawling for endpoint discovery
- `analyzer/` - Result correlation and false positive reduction
- `waf/` - WAF detection and adaptive testing
- `reporting/` - JSON/json report generation
- `cli/` - Command-line interface
- `plugins/` - Extensible plugin system
- `utils/` - Safety controls and logging

## Quick Scan Module

The `quick_scan.py` module provides advanced vulnerability detection with:

- **Multiple detection techniques**: Boolean-based, error-based, time-based, UNION-based
- **Confidence scoring**: Dynamic confidence calculation based on evidence
- **False positive reduction**: Pattern matching and similarity analysis
- **Differential analysis**: Content comparison between baseline and test responses
- **Comprehensive payload sets**: 8+ boolean, 7+ error, 5+ time, 6+ UNION payloads

Usage:
```bash
python quick_scan.py http://example.com
```
