# SQLProbe - SQL Injection Assessment Framework v2.0 (2026)

A production-grade, modular framework for authorized security testing of SQL injection vulnerabilities with modern 2026 features.

## Legal Notice

**WARNING**: This tool is provided for **authorized security testing only**. 

- Unauthorized scanning of systems you do not own or have explicit written permission to test is **illegal**.
- By using this tool, you agree to use it only in compliance with all applicable laws and with proper authorization.
- The authors assume no liability for any misuse or damage caused by this tool.

## What's New in v2.0 (2026)

- **Auto-Parameters Discovery** - Automatically finds parameters from forms, links, JavaScript, and common parameter names
- **WAF/Cloud Detection** - Detects Cloudflare, Akamai, AWS WAF, Imperva, FortiWeb, ModSecurity, Sucuri
- **CDN Identification** - Identifies CloudFront, Fastly, CDNJS, jsDelivr
- **Tech Stack Fingerprinting** - Detects React, Vue, Angular, Node.js, Python, PHP, Java, Apache, Nginx
- **Header Injection Testing** - Tests X-Forwarded-For, User-Agent, custom headers
- **Cookie Injection Testing** - Tests cookie values for SQL injection
- **JSON API Testing** - Tests JSON body parameters
- **GraphQL Testing** - Tests GraphQL endpoints
- **87+ Payloads** - Comprehensive payloads (Boolean, Error, UNION, Time-based, WAF bypass)
- **Improved Detection** - Better confidence scoring with multi-indicator analysis

## Features

- **Async Engine**: High-performance async HTTP engine with connection pooling, retry logic, and rate limiting
- **Smart Crawler**: Recursive crawling with form and parameter extraction
- **Payload Engine**: 87+ payloads across 9 categories (Boolean, Error, Time-based, UNION, Blind, GraphQL, JSON, NoSQL)
- **Detection Engine**: Multiple detection methods with confidence scoring
- **WAF Detection**: Detects and adapts to 8+ WAF systems
- **Auto-Parameter Discovery**: Forms, links, JS, common params
- **Reporting**: JSON and HTML report generation
- **Plugin System**: Extensible architecture for custom payloads and detection methods
- **CLI**: Rich command-line interface with progress display

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

## Quick Start

### Command Line

```bash
# Basic scan
python -m sqlprobe -u "http://example.com/page.php?id=1"

# With depth and concurrency
python -m sqlprobe -u "http://example.com" --depth 3 --concurrency 20

# With proxy
python -m sqlprobe -u "http://example.com" -p "http://localhost:8080"

# Generate HTML report
python -m sqlprobe -u "http://example.com" -o results --format html
```

### Advanced Scanner (Standalone)

```bash
python advanced_scan.py "https://target.com/page?id=1"
```

### Python API

```python
import asyncio
from sqlprobe.engine import AssessmentEngine
from sqlprobe.reporting import ReportGenerator

async def main():
    engine = AssessmentEngine(
        target="http://example.com/page.php?id=1",
        depth=2,
        concurrency=10,
    )
    
    results = await engine.run()
    
    report = ReportGenerator(results=results, output_format="json")
    report.generate()

asyncio.run(main())
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --target` | Target URL to test | Required |
| `-d, --depth` | Crawling depth | 2 |
| `-c, --concurrency` | Concurrent requests | 10 |
| `-t, --timeout` | Request timeout (seconds) | 30 |
| `-p, --proxy` | HTTP/HTTPS proxy | None |
| `-o, --output` | Output file path | None |
| `-f, --format` | Output format (json/html/both) | json |
| `-v, --verbose` | Increase verbosity | 0 |
| `--save-session` | Save scan session | None |
| `--load-session` | Load scan session | None |
| `--whitelist` | Allowed domains | None |

## Payload Categories

| Category | Count | Description |
|----------|-------|-------------|
| Boolean-based | 23 | Classic true/false injection |
| Error-based | 17 | SQL syntax error detection |
| UNION-based | 16 | UNION SELECT injection |
| Time-based | 14 | Blind injection with delays |
| GraphQL | 6 | GraphQL endpoint testing |
| JSON API | 4 | JSON body parameter testing |
| NoSQL | 6 | MongoDB injection |
| WAF Bypass | 10+ | Modern bypass techniques |

## Architecture

```
sqlprobe/
├── engine/           # Async HTTP engine and main assessment engine
├── payloads/         # 87+ payload generation and mutation
├── detection/       # Detection engine and result analysis
├── crawler/         # Smart web crawler
├── analyzer/        # Result correlation and analysis
├── waf/             # WAF detection and adaptation
├── reporting/       # Report generation
├── cli/            # Command-line interface
├── plugins/        # Plugin system
└── utils/          # Utilities and safety controls
```

## Safety Controls

- Domain whitelist enforcement
- Rate limiting
- Target confirmation required
- Legal warning banner
- No exploitation or data extraction
- Detection-only (no data extraction)

## Testing

```bash
python -m sqlprobe -u "https://demo.testfire.net/search.jsp?query=test" --depth 1
```

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is provided as-is for educational and authorized security testing purposes. Users are responsible for ensuring compliance with all applicable laws and regulations.