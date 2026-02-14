# Hunter MVP

Autonomous Bug Bounty Agent - SQL Injection Detection Focus

## Overview

Hunter is an AI-powered security testing tool designed for bug bounty programs. This MVP focuses on **SQL Injection detection** with a safety-first approach.

## Features

- **Subdomain Enumeration** - Automated discovery using subfinder/assetfinder
- **HTTP Probing** - Live service detection with technology fingerprinting
- **SQL Injection Detection** - Error-based and boolean-based detection
- **Safety Controls** - Risk assessment with approval gates
- **Markdown Reports** - Platform-ready vulnerability reports

## Quick Start

### 1. Setup Virtual Environment

**Windows (PowerShell):**
```powershell
.\setup.ps1
.venv\Scripts\Activate.ps1
```

**Linux/macOS:**
```bash
chmod +x setup.sh
./setup.sh
source .venv/bin/activate
```

**Manual Setup:**
```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (Linux/macOS)
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure API Key

Hunter uses the **Kimi API** (OpenAI-compatible) for autonomous SQLi detection:

1. **Get your API key** from [https://platform.moonshot.cn/](https://platform.moonshot.cn/)
   - Create an account
   - Go to API Keys → Create New Key

2. **Set the API key** (choose one method):

   **Option A: Environment variable (recommended)**
   ```powershell
   # Windows PowerShell
   $env:HUNTER_KIMI_API_KEY="your-api-key-here"
   ```
   ```bash
   # Linux/macOS
   export HUNTER_KIMI_API_KEY="your-api-key-here"
   ```

   **Option B: .env file**
   ```bash
   cp .env.example .env
   # Edit .env and set HUNTER_KIMI_API_KEY
   ```

### 3. Run Scan

```bash
# Basic scan
python -m hunter scan example.com

# With custom scope
python -m hunter scan example.com --scope "*.example.com"

# Reconnaissance only
python -m hunter scan example.com --recon-only

# Disable safe mode (requires approval for risky operations)
python -m hunter scan example.com --no-safe-mode
```

## Architecture

```
hunter/
├── main.py              # CLI entry point
├── models.py            # Core data models
├── config.py            # Configuration management
├── recon/
│   ├── subdomain.py     # Subdomain enumeration
│   └── probe.py         # HTTP probing
├── agents/
│   └── sqli_agent.py    # Autonomous SQL Injection agent
├── safety/
│   └── controller.py    # Safety controls
└── report/
    └── markdown.py      # Report generation
```

**Autonomous Agent Design:**
- Uses **Kimi API** (OpenAI-compatible) for intelligent decision-making
- AI plans the testing strategy based on target technology
- Executes tests with rate limiting and safety controls
- Reports confirmed findings with evidence

## Safety Features

- **Read-only by default** - No data modification without approval
- **Rate limiting** - Max 100 requests/minute
- **Scope enforcement** - Strict in-scope validation
- **Approval gates** - User confirmation for high-risk tests
- **Emergency stop** - Ctrl+C halts all operations

## Example Output

```
┌─────────────────────────────────────────────────────────┐
│  Hunter - Autonomous Bug Bounty Agent                   │
│  SQL Injection Detection | Safe by Default              │
└─────────────────────────────────────────────────────────┘

Target: example.com
Scope: *.example.com, example.com
Safe Mode: Enabled

Enumerating subdomains... Found 42 subdomains
Probing for live services... Found 15 live endpoints

┌─────────────────────────────────────────────────────────┐
│ Discovered Endpoints (15)                               │
├─────────────────────────────────────────────────────────┤
│ https://api.example.com              200    Express     │
│ https://admin.example.com            403    Nginx       │
│ ...
└─────────────────────────────────────────────────────────┘

Starting SQL Injection Analysis...

Confirmed Findings: 2

┌──────────┬──────────┬──────────────────────────┬───────────┐
│ Type     │ Severity │ URL                      │ Parameter │
├──────────┼──────────┼──────────────────────────┼───────────┤
│ SQLI     │ HIGH     │ https://api.example.com  │ id        │
│ SQLI     │ MEDIUM   │ https://app.example.com  │ user_id   │
└──────────┴──────────┴──────────────────────────┴───────────┘

Report saved to: ./output/hunter_report_abc123_20250215_034012.md
```

## Configuration

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Environment variables:

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `HUNTER_KIMI_API_KEY` | **Yes** | Kimi API key from [platform.moonshot.cn](https://platform.moonshot.cn/) | - |
| `HUNTER_KIMI_MODEL` | No | Model to use | `kimi-k2-thinking` |
| `HUNTER_KIMI_BASE_URL` | No | API base URL | `https://api.moonshot.cn/v1` |
| `HUNTER_MAX_REQUESTS_PER_MINUTE` | No | Rate limit | 100 |
| `HUNTER_SAFE_MODE` | No | Enable safety controls | true |
| `HUNTER_OUTPUT_DIR` | No | Report output directory | `./output` |

### Troubleshooting API Issues

**Error: "Kimi API key not set"**
```bash
# Set the environment variable
$env:HUNTER_KIMI_API_KEY="your-key"        # Windows PowerShell
export HUNTER_KIMI_API_KEY="your-key"      # Linux/macOS
```

**Error: "Invalid API key" or 401 Unauthorized**
- Verify your key at: https://platform.moonshot.cn/
- Check for typos or extra spaces
- Ensure the key has not expired

**Error: "Rate limit exceeded"**
- Kimi API has rate limits based on your tier
- Hunter has built-in rate limiting (configurable)

## Limitations (MVP)

- Single vulnerability type (SQLi only)
- No authentication support
- Basic subdomain enumeration
- No duplicate detection
- Manual report submission

## Roadmap

- [ ] Add XSS agent
- [ ] Add IDOR/BOLA agent
- [ ] HackerOne API integration
- [ ] Knowledge graph (Neo4j)
- [ ] Parallel agent execution

## Development

### Activate Virtual Environment

```bash
# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

### Deactivate

```bash
deactivate
```

### Adding New Dependencies

```bash
# Add to requirements.txt
pip install new-package
pip freeze | findstr new-package >> requirements.txt  # Windows
pip freeze | grep new-package >> requirements.txt     # Linux/macOS
```

## License

MIT
