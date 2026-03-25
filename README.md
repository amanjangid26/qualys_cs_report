# Qualys Container Security - Image Report Generator

Enterprise CLI tool that pulls container image records from Qualys CSAPI, enriches them with running container counts, EOL base OS status, and software lifecycle dates, and produces a unified CSV + JSON report.

[![Version](https://img.shields.io/badge/version-2.2.0-blue)](https://github.com/amanjangid26/qualys_cs_report)
[![Python](https://img.shields.io/badge/python-3.8%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-orange)](LICENSE)

---

## Features

| Feature | Description |
|---------|-------------|
| **Single CSV output** | Fully denormalized — every image, software, vulnerability, lifecycle date, and container count in one file. Open in Excel and filter. |
| **EOL Base OS detection** | Compares image SHAs between main API and EOL-filtered API. Match → `EOL_Base_OS = True`. |
| **Container count enrichment** | Queries running container count per image SHA in parallel. Know your blast radius. |
| **Software lifecycle dates** | GA (general availability), EOL (end of life), and EOS (end of support) dates for installed packages. |
| **Image source tracking** | Shows where Qualys discovered the image: GENERAL, REGISTRY, HOST, CICD, etc. |
| **Parallel execution** | Phase 3 (container counts) uses multiple threads with coordinated rate limiting. |
| **Idempotent** | Checkpoint after each phase. Re-run to resume, not restart. `--force` for fresh. |
| **Global rate limiter** | All threads coordinate via token bucket. Reads `X-RateLimit-Remaining`, auto-slows, honours `Retry-After` on 429. |
| **Custom filters** | Append any Qualys filter with `-f` (e.g. `operatingSystem:Ubuntu`, `repo.registry:docker.io`). |
| **Atomic writes** | All output files written to temp first, then renamed. No corrupt files on crash. |
| **Lock file** | Prevents concurrent runs against the same output directory. |
| **Signal handling** | `Ctrl+C` saves state and exits cleanly. Re-run to resume. |

---

## Prerequisites

- **Python 3.8+**
- **curl**

```bash
# Ubuntu / Debian
sudo apt-get install -y python3 curl

# RHEL / Amazon Linux
sudo yum install -y python3 curl

# macOS
brew install python3 curl
```

No pip packages required — uses only Python standard library.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/amanjangid26/qualys_cs_report.git
cd qualys_cs_report

# 2. Set your token
export QUALYS_ACCESS_TOKEN="eyJ..."

# 3. Run
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com"
```

Reports land in `./qualys_report_output/`.

---

## Getting Your Access Token

1. Log in to the **Qualys Platform**
2. Navigate to **CS (Container Security)** module
3. Go to **Configurations** → **Access Token** tab
4. Under **LINUX**, click **COPY**
5. `export QUALYS_ACCESS_TOKEN="eyJ..."`

> **Never commit tokens to git.** Use environment variables, Vault, or a secrets manager.

---

## Usage

```bash
# Basic — images in use last 30 days
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com"

# Dry run — preview config, no API calls
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" --dry-run

# Skip container counts (much faster)
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" --skip-containers

# Custom filter — only Ubuntu images
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" \
    -f "operatingSystem:Ubuntu"

# Custom filter — specific registry
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" \
    -f "repo.registry:docker.io"

# Custom filter — images with critical vulns
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" \
    -f "vulnerabilities.severity:5"

# More threads + faster API calls (for large environments)
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" \
    --concurrency 10 --cps 3

# Custom lookback
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" -d 7 -D 5

# Force fresh run (ignore checkpoint)
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" --force

# Via proxy
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" \
    -C "--proxy http://proxy.corp.com:8080"

# Quiet (cron/CI)
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" -q
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-g`, `--gateway` | Qualys gateway URL | `$QUALYS_GATEWAY` |
| `-t`, `--token` | Access token | `$QUALYS_ACCESS_TOKEN` |
| `-l`, `--limit` | Results per page (1–250) | 250 |
| `-d`, `--days` | Image lookback days | 30 |
| `-D`, `--container-scan-days` | Container scan lookback | 3 |
| `-f`, `--filter` | Extra filter appended with AND (e.g. `operatingSystem:Ubuntu`) | — |
| `-o`, `--output-dir` | Output directory | `./qualys_report_output` |
| `--skip-containers` | Skip container count API calls (faster) | false |
| `--force` | Ignore checkpoint, start fresh | false |
| `--concurrency` | Parallel threads for container counts | 5 |
| `--cps` | Max API calls per second (across all threads) | 2 |
| `-r`, `--retries` | Max retries per API call | 2 |
| `-C`, `--curl-extra` | Extra curl args (e.g. `--proxy`) | — |
| `-v`, `--verbose` | Debug output | false |
| `-q`, `--quiet` | Suppress console output | false |
| `--dry-run` | Preview config, no API calls | false |

All flags can also be set via environment variables with `QUALYS_` prefix.

---

## Output

```
qualys_report_output/
├── qualys_cs_unified_report.csv     ← Main report (open in Excel)
├── images_full_report.json          ← Complete JSON
├── run_summary.json                 ← Machine-readable metadata
├── report_YYYYMMDD_HHMMSS.log      ← Execution log
├── pages/                           ← Raw API responses (for resume)
└── raw/                             ← Intermediate data
```

### CSV Columns (32)

| # | Column | Description |
|---|--------|-------------|
| 1 | `Image_ID` | Short 12-char image ID |
| 2 | `Image_SHA` | Full SHA256 |
| 3 | `Operating_System` | e.g. Debian Linux 12.13 |
| 4 | `EOL_Base_OS` | `True`/`False` if OS present; empty for distroless/scratch images |
| 5 | `Architecture` | arm64, amd64 |
| 6 | `Image_Created` | Creation timestamp (empty if unavailable) |
| 7 | `Image_Last_Scanned` | Last Qualys scan |
| 8 | `Image_Scan_Types` | SCA, STATIC, DYNAMIC (image-level) |
| 9 | `Image_Source` | Where Qualys found the image: GENERAL, REGISTRY, HOST, CICD |
| 10 | `Registry` | e.g. mcr.microsoft.com |
| 11 | `Repository` | e.g. aks/msi/addon-token-adapter |
| 12 | `Image_Tag` | e.g. v1.2.3, latest |
| 13 | `Risk_Score` | Qualys TruRisk (0–1000) |
| 14 | `Max_QDS_Score` | Max QDS score |
| 15 | `QDS_Severity` | CRITICAL / HIGH / MEDIUM / LOW |
| 16 | `Total_Vulnerabilities_On_Image` | Vuln count |
| 17 | `Running_Container_Count` | Active containers using this image |
| 18 | `Software_Name` | Installed package |
| 19 | `Software_Installed_Version` | Current version |
| 20 | `Software_Fix_Version` | Fix version |
| 21 | `Software_Package_Path` | File path of the package (e.g. app/bin/myapp) |
| 22 | `Software_Lifecycle_Stage` | EOL/EOS, GA, Beta, etc. |
| 23 | `Software_GA_Date` | General availability date |
| 24 | `Software_EOL_Date` | End of life date |
| 25 | `Software_EOS_Date` | End of support date |
| 26 | `Vuln_QID` | Qualys vulnerability ID |
| 27 | `Vuln_Scan_Type` | How this vuln was found (SCA/STATIC/DYNAMIC) |
| 28 | `Vuln_Type_Detected` | CONFIRMED / POTENTIAL |
| 29 | `Vuln_First_Found` | First detection date |
| 30 | `Vuln_Affected_Software_Name` | Affected package |
| 31 | `Vuln_Affected_Software_Version` | Affected version |
| 32 | `Vuln_Fix_Version` | Remediation version |

### Row Logic

| Row type | Driven by | Software cols | Vuln cols |
|----------|-----------|--------------|-----------|
| **Vulnerability** | Each QID × affected software | Filled | Filled |
| **Software-only** | Installed package with no vuln | Filled | Blank |
| **Bare image** | Image with no data | Blank | Blank |

Multi-registry images get **separate rows per registry** — no pipe-delimited values, clean Excel filtering.

---

## How It Works

### Phase 1: Fetch images
Calls `/images/list` with pagination (follows `Link` header). Saves each page to `pages/` for resume.

### Phase 2: Fetch EOL images
Calls `/images/list` with `vulnerabilities.title:EOL` filter. Collects SHAs. Compares against Phase 1 SHAs: match → `EOL_Base_OS = True`.

### Phase 3: Container counts (parallel)
For each unique image SHA, calls `/containers` to get running container count. Uses multiple threads with a global rate limiter. HTTP 204 = 0 containers (not an error). Checkpoints every 100 SHAs.

### Phase 4: Report generation
Denormalizes everything into a single CSV + full JSON. Atomic writes.

### Idempotency
Each phase writes a checkpoint file. On re-run:
- **Same config** → resumes from last checkpoint
- **Config changed** → starts fresh automatically
- **`--force`** → clears checkpoint, starts fresh
- **Ctrl+C mid-run** → saves state, resume on next run

### Rate Limiting
```
All threads call acquire() before each API call
───────────────────────────────────────────────
remaining > 20       →  continue at configured CPS
remaining ≤ 20       →  slow to 1 call/sec
remaining = 0        →  ALL threads pause for window reset + 5s
HTTP 429             →  ALL threads pause (Retry-After or window reset)
```

---

## Performance Tuning

| Scenario | Recommended flags |
|----------|-------------------|
| Small environment (< 100 images) | Default settings |
| Medium (100–1000 images) | `--concurrency 10 --cps 3` |
| Large (1000–5000 images) | `--concurrency 10 --cps 4` |
| Very large (5000+ images) | `--concurrency 15 --cps 5` |
| Quick scan (skip containers) | `--skip-containers` |

---

## Supported Gateways

| Region | URL |
|--------|-----|
| US 1 | `https://gateway.qg1.apps.qualys.com` |
| US 2 | `https://gateway.qg2.apps.qualys.com` |
| US 3 | `https://gateway.qg3.apps.qualys.com` |
| US 4 | `https://gateway.qg4.apps.qualys.com` |
| EU 1 | `https://gateway.qg1.apps.qualys.eu` |
| EU 2 | `https://gateway.qg2.apps.qualys.eu` |
| Canada | `https://gateway.qg1.apps.qualys.ca` |
| India | `https://gateway.qg1.apps.qualys.in` |
| Australia | `https://gateway.qg1.apps.qualys.com.au` |
| UAE | `https://gateway.qg1.apps.qualys.ae` |
| UK | `https://gateway.qg1.apps.qualys.co.uk` |
| KSA | `https://gateway.qg1.apps.qualysksa.com` |
| US Gov | `https://gateway.gov1.qualys.us` |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `HTTP 401` | Token expired — regenerate from Qualys CS → Configurations → Access Token |
| `HTTP 403` | Token lacks CSAPI scope |
| `HTTP 404` | Wrong gateway URL — check your region |
| `HTTP 429` | Handled automatically. Reduce `--cps` if persistent. |
| `Another instance running` | Wait, or use `--force` |
| `Running_Container_Count = N/A` | Used `--skip-containers` |
| `Image_Created empty` | Qualys API returns epoch 0 for some images (no creation date recorded) |
| `Operating_System empty` | Qualys couldn't detect the base OS (scratch/distroless images) |
| `EOL_Base_OS empty` | No OS detected — EOL evaluation is skipped for distroless images |
| Slow run | Use `--skip-containers`, or increase `--concurrency` and `--cps` |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
