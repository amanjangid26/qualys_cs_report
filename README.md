# Qualys Container Security — Image Report Generator

Enterprise CLI tool that pulls container image records from Qualys CSAPI, enriches them with running container counts, EOL base OS status, and software lifecycle dates, and produces a unified CSV + JSON report.

[![Version](https://img.shields.io/badge/version-3.0.0-blue)](https://github.com/amanjangid26/qualys_cs_report)
[![Python](https://img.shields.io/badge/python-3.8%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-orange)](LICENSE)

---

## Features

| Feature | Description |
|---------|-------------|
| **Automatic JWT authentication** | Uses Qualys username + password to auto-generate a JWT token. No manual token management. |
| **Single CSV output** | Fully denormalized — every image, software, lifecycle date, and container count in one file. |
| **EOL Base OS detection** | Compares image SHAs between main API and EOL-filtered API. Match → `EOL_Base_OS = True`. Empty for distroless. |
| **Container count enrichment** | Queries running container count per image SHA in parallel. Know your blast radius. |
| **Software lifecycle dates** | GA, EOL, and EOS dates for installed packages. |
| **Package path tracking** | Shows where each software was found inside the image. |
| **Distroless-aware** | Images with no OS → `EOL_Base_OS` left empty (not evaluated). |
| **Parallel execution** | Phase 3 uses multiple threads with coordinated global rate limiting. |
| **Idempotent** | Checkpoint after each phase. Re-run to resume, not restart. |
| **Custom filters** | Append any Qualys filter with `-f`. |

---

## Prerequisites

- **Python 3.8+**
- **curl**

```bash
# Ubuntu / Debian
sudo apt-get install -y python3 curl

# macOS
brew install python3 curl
```

No pip packages required.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/amanjangid26/qualys_cs_report.git
cd qualys_cs_report

# 2. Set credentials (use SINGLE QUOTES to handle special characters)
export QUALYS_USERNAME='myuser'
export QUALYS_PASSWORD='myP@ss&word#1!'

# 3. Run
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com"
```

The script automatically generates a JWT token and uses it for all API calls. Reports land in `./qualys_report_output/`.

---

## Authentication

The script uses the [Qualys Authentication API](https://docs.qualys.com/en/cs/1.41.0/mergedProjects/container_security_apis/get_started/get_started.htm) to generate a JWT token:

```
POST https://<gateway>/auth
Content-Type: application/x-www-form-urlencoded
Body: username=<user>&password=<pass>&token=true
```

The token is valid for 4 hours. You don't need to manage tokens manually — just provide username + password.

### Setting Credentials

Use **single quotes** when exporting credentials — this safely handles special characters like `!`, `$`, `&`, `#`, spaces, etc.

```bash
export QUALYS_USERNAME='admin@corp.com'
export QUALYS_PASSWORD='P@ss&word#1!$pecial'
```

Or pass directly via flags:
```bash
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" \
    -u 'admin@corp.com' -p 'P@ss&word#1!'
```

The script URL-encodes credentials before sending them to the Qualys `/auth` endpoint, so all special characters work correctly.

> **Never commit credentials to git.** Use environment variables, Vault, or a secrets manager.

---

## Usage

```bash
# Basic
export QUALYS_USERNAME='myuser'
export QUALYS_PASSWORD='myP@ssword'
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com"

# Dry run
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" --dry-run

# Skip container counts (faster)
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" --skip-containers

# Custom filter
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" \
    -f "operatingSystem:Ubuntu"

# More threads
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" \
    --concurrency 10 --cps 3

# Force fresh run
python3 qualys_cs_report.py -g "https://gateway.qg2.apps.qualys.com" --force
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--username` | Qualys username | `$QUALYS_USERNAME` |
| `-p`, `--password` | Qualys password | `$QUALYS_PASSWORD` |
| `-g`, `--gateway` | Qualys gateway URL | `$QUALYS_GATEWAY` |
| `-l`, `--limit` | Results per page (1–250) | 250 |
| `-d`, `--days` | Image lookback days | 30 |
| `-D`, `--container-scan-days` | Container scan lookback | 3 |
| `-f`, `--filter` | Extra filter (e.g. `operatingSystem:Ubuntu`) | — |
| `-o`, `--output-dir` | Output directory | `./qualys_report_output` |
| `--skip-containers` | Skip container count API calls | false |
| `--force` | Ignore checkpoint, start fresh | false |
| `--concurrency` | Parallel threads | 5 |
| `--cps` | Max API calls/sec | 2 |
| `-r`, `--retries` | Max retries per call | 2 |
| `-C`, `--curl-extra` | Extra curl args | — |
| `-v`, `--verbose` | Debug output | false |
| `-q`, `--quiet` | Suppress console | false |
| `--dry-run` | Preview config only | false |

---

## Output

```
qualys_report_output/
├── qualys_cs_unified_report.csv     ← Main report
├── images_full_report.json          ← Complete JSON
├── run_summary.json                 ← Metadata
├── report_YYYYMMDD_HHMMSS.log      ← Log
├── pages/                           ← API page cache
└── raw/                             ← Intermediate data
```

### CSV Columns (25)

| # | Column | Description |
|---|--------|-------------|
| 1 | `Image_ID` | Short 12-char image ID |
| 2 | `Image_SHA` | Full SHA256 |
| 3 | `Operating_System` | e.g. Debian Linux 12.13 |
| 4 | `EOL_Base_OS` | `True`/`False` if OS present; empty for distroless |
| 5 | `Architecture` | arm64, amd64 |
| 6 | `Image_Created` | Creation timestamp (empty if unavailable) |
| 7 | `Image_Last_Scanned` | Last Qualys scan |
| 8 | `Image_Scan_Types` | SCA, STATIC, DYNAMIC |
| 9 | `Image_Source` | GENERAL, REGISTRY, HOST, CICD |
| 10 | `Registry` | e.g. mcr.microsoft.com |
| 11 | `Repository` | e.g. aks/msi/addon-token-adapter |
| 12 | `Image_Tag` | e.g. v1.2.3, latest |
| 13 | `Risk_Score` | Qualys TruRisk (0–1000) |
| 14 | `Max_QDS_Score` | Max QDS score |
| 15 | `QDS_Severity` | CRITICAL / HIGH / MEDIUM / LOW |
| 16 | `Running_Container_Count` | Active containers using this image |
| 17 | `Software_Name` | Installed package |
| 18 | `Software_Installed_Version` | Current version |
| 19 | `Software_Fix_Version` | Fix version |
| 20 | `Software_Package_Path` | File path inside the image |
| 21 | `Software_Lifecycle_Stage` | EOL/EOS, GA, Beta, etc. |
| 22 | `Software_GA_Date` | General availability date |
| 23 | `Software_EOL_Date` | End of life date |
| 24 | `Software_EOS_Date` | End of support date |
| 25 | `Software_Scan_Type` | SCA, STATIC, DYNAMIC (per software) |

---

## How It Works

### Phase 0: Authentication
Calls `POST /auth` with username + password to get a JWT token (valid 4 hours).

### Phase 1: Fetch images
Paginated calls to `/images/list`. Saves pages for resume.

### Phase 2: EOL detection
Fetches images with `vulnerabilities.title:EOL` filter. Compares SHAs. Distroless images (no OS) → EOL left empty.

### Phase 3: Container counts (parallel)
Calls `/containers` per SHA using thread pool. HTTP 204 = 0 containers. Rate-limit coordinated.

### Phase 4: Report generation
Flat CSV + JSON. Atomic writes.

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
| `HTTP 401` at auth | Wrong username/password |
| `HTTP 401` during API calls | JWT expired (>4 hours). Re-run to get a new token. |
| `HTTP 403` | User lacks CS API Access permission |
| `HTTP 429` | Handled automatically. Reduce `--cps` if persistent. |
| `EOL_Base_OS empty` | Distroless image — no OS to evaluate |
| `Operating_System empty` | Qualys couldn't detect the base OS |
| `Image_Created empty` | Qualys has no creation date for this image |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
