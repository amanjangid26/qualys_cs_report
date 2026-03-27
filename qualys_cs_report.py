#!/usr/bin/env python3
"""
=============================================================================
  Qualys Container Security - Image Report Generator
  Version: 3.0.0
=============================================================================

  WHAT THIS SCRIPT DOES:

  It talks to Qualys Container Security APIs and builds a single CSV + JSON
  report containing every container image, its installed software, lifecycle
  dates (GA/EOL/EOS), running container count, and whether the base operating
  system is end-of-life.

  AUTHENTICATION:

  Uses Qualys username + password to automatically generate a JWT token.
  The token is generated at startup by calling:
      POST https://<gateway>/auth
      username=<user>&password=<pass>&token=true
  The JWT is valid for 4 hours and is used for all subsequent API calls.
  No need to manually copy tokens from the Qualys UI.

  HOW IT WORKS (5 phases):

  Phase 0 — AUTHENTICATION
      Calls the Qualys /auth endpoint with username + password to get a
      JWT (JSON Web Token). This token is then used in the Authorization
      header for all subsequent API calls.

  Phase 1 — IMAGE LIST
      Calls the Qualys Image Bulk API to fetch all container images that
      were in use during the last N days. Handles pagination automatically.

  Phase 2 — EOL BASE OS DETECTION
      Calls the same Image API with "vulnerabilities.title:EOL" filter.
      Compares SHAs against Phase 1:
          SHA match AND image has an OS → EOL_Base_OS = True
          SHA only in Phase 1 AND has OS → EOL_Base_OS = False
          Image has NO OS (distroless)   → EOL_Base_OS = empty

  Phase 3 — CONTAINER COUNTS (parallel)
      For each unique image SHA, calls the Container API in parallel to
      find running container count. Uses global rate limiter across threads.
      HTTP 204 = 0 containers (valid, not an error).

  Phase 4 — REPORT GENERATION
      Builds a single flat CSV (25 columns) + JSON report.
      One row per (image × repo × software). No vulnerability columns.

  Phase 5 — RUN SUMMARY

  IDEMPOTENT: re-run resumes from checkpoint. --force for fresh start.
  PREREQUISITES: Python 3.8+, curl
=============================================================================
"""

# =============================================================================
# IMPORTS
# =============================================================================
import argparse
import atexit
import concurrent.futures
import csv
import hashlib
import json
import logging
import os
import random
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from urllib.parse import quote as url_encode  # URL-encode special chars in credentials

VERSION = "3.0.0"

# =============================================================================
# DEFAULTS
# =============================================================================
DEFAULT_GATEWAY             = "https://gateway.qg2.apps.qualys.com"
DEFAULT_API_VERSION         = "v1.3"
DEFAULT_PAGE_LIMIT          = 250
DEFAULT_IMAGE_LOOKBACK_DAYS = 30
DEFAULT_CONTAINER_SCAN_DAYS = 3
DEFAULT_MAX_RETRIES         = 2
DEFAULT_CONNECT_TIMEOUT     = 15
DEFAULT_REQUEST_TIMEOUT     = 60
DEFAULT_THREAD_COUNT        = 5
DEFAULT_CALLS_PER_SECOND    = 2

# =============================================================================
# SIGNAL HANDLING
# =============================================================================
shutdown_requested = False

def handle_shutdown_signal(signal_number, _frame):
    global shutdown_requested
    print(f"\n[!] {signal.Signals(signal_number).name} — saving progress...", file=sys.stderr)
    shutdown_requested = True

signal.signal(signal.SIGINT, handle_shutdown_signal)
signal.signal(signal.SIGTERM, handle_shutdown_signal)

def check_if_shutdown_requested():
    if shutdown_requested:
        raise SystemExit(130)

# =============================================================================
# HELPERS
# =============================================================================
def convert_to_safe_string(value):
    """None or literal string 'None' → empty. Everything else → str."""
    if value is None or value == "None":
        return ""
    return str(value)

def convert_epoch_ms_to_iso(epoch_milliseconds):
    """Qualys epoch-ms → ISO 8601. '0' or null → empty."""
    if not epoch_milliseconds or str(epoch_milliseconds) == "0":
        return ""
    try:
        seconds = int(epoch_milliseconds) / 1000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return str(epoch_milliseconds)

def write_json_atomically(file_path, data):
    """Write JSON via temp file → atomic rename."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(file_path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, file_path)
    except Exception:
        try: os.remove(tmp)
        except OSError: pass
        raise

def format_duration(total_seconds):
    if total_seconds < 60: return f"{total_seconds}s"
    if total_seconds < 3600: return f"{total_seconds//60}m{total_seconds%60}s"
    return f"{total_seconds//3600}h{(total_seconds%3600)//60}m"

def remove_file_silently(file_path):
    try: os.remove(file_path)
    except OSError: pass

def generate_config_fingerprint(args):
    config_string = (f"{args.gateway}|{args.days}|{args.container_scan_days}"
                     f"|{args.limit}|{args.skip_containers}|{args.filter or ''}")
    return hashlib.sha256(config_string.encode()).hexdigest()[:16]

def build_image_api_filter(lookback_days, extra_filter=""):
    base = f"imagesInUse%3A%60%5Bnow-{lookback_days}d%20...%20now%5D%60"
    if extra_filter:
        return f"{base}%20and%20{extra_filter.replace(' ', '%20')}"
    return base

# =============================================================================
# LOGGING
# =============================================================================
def setup_logging(output_directory, verbose_mode, quiet_mode):
    logger = logging.getLogger("qualys")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    log_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_file_path = os.path.join(output_directory, log_filename)
    fh = logging.FileHandler(log_file_path)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    logger.addHandler(fh)
    if not quiet_mode:
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG if verbose_mode else logging.INFO)
        ch.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(ch)
    return logger, log_file_path

# =============================================================================
# LOCK + CHECKPOINT
# =============================================================================
def acquire_lock_file(output_directory, force_mode):
    lock_path = os.path.join(output_directory, ".lock")
    if os.path.exists(lock_path):
        try:
            existing_pid = int(open(lock_path).read().strip())
            os.kill(existing_pid, 0)
            if not force_mode:
                print(f"ERROR: Another instance running (PID {existing_pid}). Use --force.",
                      file=sys.stderr)
                sys.exit(1)
        except (ValueError, ProcessLookupError, PermissionError):
            pass
    open(lock_path, "w").write(str(os.getpid()))
    atexit.register(lambda: remove_file_silently(lock_path))

class CheckpointManager:
    def __init__(self, output_directory, config_fingerprint):
        self.file_path = os.path.join(output_directory, ".checkpoint.json")
        self.fingerprint = config_fingerprint
        self.state = {}
        if os.path.exists(self.file_path):
            try:
                self.state = json.load(open(self.file_path))
                if self.state.get("fingerprint") != config_fingerprint:
                    self.state = {}
            except (json.JSONDecodeError, KeyError):
                self.state = {}

    def is_phase_complete(self, phase_name):
        return self.state.get(phase_name) is True

    def mark_complete(self, phase_name):
        self.state[phase_name] = True
        self.state["fingerprint"] = self.fingerprint
        write_json_atomically(self.file_path, self.state)

    def clear_all(self):
        remove_file_silently(self.file_path)
        self.state = {}

# =============================================================================
# JWT AUTHENTICATION
# Calls POST /auth with username + password to get a JWT token.
# The token is valid for 4 hours.
# =============================================================================
def generate_jwt_token(gateway_url, username, password, connect_timeout, logger):
    """Authenticate to Qualys and return a JWT token.

    Calls:
        POST https://<gateway>/auth
        Content-Type: application/x-www-form-urlencoded
        Body: username=<user>&password=<pass>&token=true

    IMPORTANT: Username and password are URL-encoded before being sent.
    This handles special characters like & = + @ ! $ # spaces etc.
    Without encoding, a password like "P@ss&word" would break the form body
    because & is the field separator in application/x-www-form-urlencoded.

    Returns the JWT string, or exits on failure.
    """
    auth_url = f"{gateway_url.rstrip('/')}/auth"
    logger.info(f"  Authenticating as '{username}'...")

    # URL-encode username and password to handle special characters.
    # quote(string, safe='') encodes EVERYTHING including / @ : etc.
    # Example: "P@ss&word#1" → "P%40ss%26word%231"
    encoded_username = url_encode(username, safe='')
    encoded_password = url_encode(password, safe='')

    cmd = [
        "curl", "-s", "-w", "\n%{http_code}",
        "--connect-timeout", str(connect_timeout),
        "--max-time", "30",
        "-X", "POST", auth_url,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "-d", f"username={encoded_username}&password={encoded_password}&token=true",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines = result.stdout.strip().split("\n")
        # Last line is the HTTP status code (from -w), everything before is the body
        http_code = int(lines[-1]) if lines[-1].isdigit() else 0
        response_body = "\n".join(lines[:-1]).strip()
    except Exception as error:
        logger.error(f"  Authentication failed: {error}")
        sys.exit(1)

    if http_code in (200, 201) and response_body:
        # The response body IS the JWT token (plain text, not JSON)
        # Qualys returns 200 or 201 depending on the platform version
        token = response_body.strip()
        if token.startswith("eyJ"):
            logger.info(f"  Token obtained: {token[:15]}...{token[-6:]} (valid 4 hours)")
            return token
        else:
            logger.error(f"  Unexpected auth response: {response_body[:100]}")
            sys.exit(1)
    elif http_code == 401:
        logger.error("  Authentication failed: invalid username or password.")
        sys.exit(1)
    else:
        logger.error(f"  Authentication failed: HTTP {http_code}")
        if response_body:
            logger.error(f"  Response: {response_body[:200]}")
        sys.exit(1)

# =============================================================================
# GLOBAL RATE LIMITER
# =============================================================================
class GlobalRateLimiter:
    def __init__(self, max_calls_per_second, logger):
        self.minimum_interval = 1.0 / max_calls_per_second
        self.logger = logger
        self.lock = threading.Lock()
        self.last_call_time = 0.0
        self.global_pause_until = 0.0
        self.last_known_remaining = None
        self.last_known_window = None
        self.total_throttle_events = 0
        self.total_throttle_seconds = 0

    def acquire(self):
        while True:
            check_if_shutdown_requested()
            with self.lock:
                now = time.time()
                if now < self.global_pause_until:
                    wait = self.global_pause_until - now
                    self.lock.release(); time.sleep(wait); self.lock.acquire(); continue
                elapsed = now - self.last_call_time
                if elapsed < self.minimum_interval:
                    wait = self.minimum_interval - elapsed
                    self.lock.release(); time.sleep(wait); self.lock.acquire(); continue
                self.last_call_time = time.time()
                return

    def read_rate_limit_headers(self, header_file_path):
        if not os.path.exists(header_file_path): return
        remaining = window = None
        try:
            for line in open(header_file_path):
                lo = line.lower().strip()
                if lo.startswith("x-ratelimit-remaining:"): remaining = int(line.split(":",1)[1].strip())
                elif lo.startswith("x-ratelimit-window-sec:"): window = int(line.split(":",1)[1].strip())
        except: return
        with self.lock:
            if remaining is not None: self.last_known_remaining = remaining
            if window is not None: self.last_known_window = window
            if remaining is not None and remaining <= 0:
                pause = (window or 60) + 5
                self.global_pause_until = time.time() + pause
                self.logger.warning(f"  Rate limit exhausted — ALL threads pausing {pause}s")
                self.total_throttle_events += 1; self.total_throttle_seconds += pause
            elif remaining is not None and remaining <= 20:
                self.minimum_interval = max(self.minimum_interval, 1.0)

    def handle_http_429(self, header_file_path):
        retry_after = None
        if os.path.exists(header_file_path):
            try:
                for line in open(header_file_path):
                    if line.lower().strip().startswith("retry-after:"):
                        retry_after = int(line.split(":",1)[1].strip())
            except: pass
        pause = retry_after or (self.last_known_window or 30) + 5
        with self.lock:
            self.global_pause_until = time.time() + pause
            self.logger.warning(f"  HTTP 429 — ALL threads pausing {pause}s")
            self.total_throttle_events += 1; self.total_throttle_seconds += pause

# =============================================================================
# API CLIENT
# =============================================================================
class QualysApiClient:
    def __init__(self, gateway_url, access_token, max_retries,
                 connect_timeout, request_timeout, extra_curl_args,
                 rate_limiter, logger):
        self.gateway = gateway_url.rstrip("/")
        self.token = access_token
        self.max_retries = max_retries
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout
        self.extra_curl_args = extra_curl_args
        self.rate_limiter = rate_limiter
        self.logger = logger
        self._counter_lock = threading.Lock()
        self._total_api_calls = 0
        self._total_retries = 0
        self._total_errors = 0

    @property
    def total_api_calls(self):
        with self._counter_lock: return self._total_api_calls
    @property
    def total_retries(self):
        with self._counter_lock: return self._total_retries
    @property
    def total_errors(self):
        with self._counter_lock: return self._total_errors

    def _increment_counters(self, calls=0, retries=0, errors=0):
        with self._counter_lock:
            self._total_api_calls += calls; self._total_retries += retries; self._total_errors += errors

    def make_request(self, url, output_file_path, keep_headers=False):
        """200=success, 204=no content (valid), 429/5xx=retry, 401/403/404=fatal, 0=failed."""
        for attempt in range(self.max_retries + 1):
            check_if_shutdown_requested()
            if attempt > 0:
                delay = random.uniform(1, min(15, 2 ** attempt))
                self.logger.debug(f"  Retry {attempt}/{self.max_retries} in {delay:.0f}s")
                time.sleep(delay)
                self._increment_counters(retries=1)

            self.rate_limiter.acquire()
            header_file = output_file_path + ".hdr"
            curl_command = [
                "curl", "-s", "-o", output_file_path, "-D", header_file, "-w", "%{http_code}",
                "--connect-timeout", str(self.connect_timeout), "--max-time", str(self.request_timeout),
                "-X", "GET", url, "-H", "Accept: application/json",
                "-H", f"Authorization: Bearer {self.token}",
            ]
            if self.extra_curl_args:
                curl_command.extend(self.extra_curl_args.split())

            try:
                result = subprocess.run(curl_command, capture_output=True, text=True)
                http_code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            except Exception as error:
                self.logger.debug(f"  curl error: {error}")
                self._increment_counters(calls=1, errors=1); continue

            self._increment_counters(calls=1)
            self.rate_limiter.read_rate_limit_headers(header_file)

            if http_code in (200, 204):
                if not keep_headers: remove_file_silently(header_file)
                return http_code
            if http_code == 401:
                self.logger.error("HTTP 401 — JWT token expired or invalid. Re-run to generate a new one.")
                sys.exit(1)
            if http_code == 403:
                self.logger.error("HTTP 403 — Insufficient permissions."); sys.exit(1)
            if http_code == 404:
                self.logger.error(f"HTTP 404 — {url}"); sys.exit(1)
            if http_code == 429:
                self.rate_limiter.handle_http_429(header_file)
            else:
                self.logger.debug(f"  HTTP {http_code}")
            remove_file_silently(header_file)
            self._increment_counters(errors=1)
        return 0

    def fetch_all_pages(self, initial_url, pages_directory, label, page_size):
        all_records = []; current_page = 1; current_url = initial_url
        while current_url:
            check_if_shutdown_requested()
            page_file = os.path.join(pages_directory, f"{label}_{current_page:04d}.json")
            header_file = page_file + ".hdr"
            if os.path.exists(page_file):
                try: page_data = json.load(open(page_file)).get("data", [])
                except: page_data = None
                if isinstance(page_data, list) and len(page_data) > 0:
                    next_url = self._extract_next_page_url(header_file)
                    if next_url:
                        all_records.extend(page_data)
                        self.logger.info(f"  {label} page {current_page}: {len(page_data)} (cached)")
                        current_url = next_url; current_page += 1; continue
                    elif len(page_data) < page_size:
                        all_records.extend(page_data)
                        self.logger.info(f"  {label} page {current_page}: {len(page_data)} (cached, last)")
                        break
                    else:
                        self.logger.info(f"  {label} page {current_page}: cached but Link lost — re-fetching")
            self.logger.info(f"  Fetching {label} page {current_page}...")
            code = self.make_request(current_url, page_file, keep_headers=True)
            if code != 200: self.logger.error(f"  Failed {label} page {current_page} (HTTP {code})"); break
            try: page_data = json.load(open(page_file)).get("data", [])
            except: break
            if not isinstance(page_data, list): break
            all_records.extend(page_data)
            self.logger.info(f"  {label} page {current_page}: {len(page_data)} (total: {len(all_records)})")
            next_url = self._extract_next_page_url(header_file)
            if next_url:
                if current_page > 1:
                    remove_file_silently(os.path.join(pages_directory, f"{label}_{current_page-1:04d}.json.hdr"))
                current_url = next_url; current_page += 1
            else: remove_file_silently(header_file); break
        remove_file_silently(os.path.join(pages_directory, f"{label}_{current_page:04d}.json.hdr"))
        self.logger.info(f"  {label}: {len(all_records)} total, {current_page} pages")
        return all_records

    @staticmethod
    def _extract_next_page_url(header_file_path):
        if not os.path.exists(header_file_path): return ""
        try:
            for line in open(header_file_path):
                if line.lower().startswith("link:"):
                    match = re.search(r'<([^>]+)>;rel=next', line)
                    if match: return match.group(1)
        except: pass
        return ""

# =============================================================================
# PARALLEL CONTAINER COUNTS
# =============================================================================
def fetch_container_counts_parallel(api_client, base_api_url, image_shas, container_scan_days,
                                     existing_counts, raw_directory, thread_count, logger):
    shas_to_fetch = [sha for sha in image_shas if sha not in existing_counts]
    if not shas_to_fetch:
        logger.info(f"  All {len(image_shas)} cached"); return existing_counts
    logger.info(f"  {len(shas_to_fetch)} to fetch, {len(existing_counts)} cached — {thread_count} threads")
    counts_file = os.path.join(raw_directory, "container_counts.json")
    completed = 0; counter_lock = threading.Lock(); t0 = time.time()

    def fetch_single(sha):
        nonlocal completed
        url = (f"{base_api_url}/containers?filter=state%3A%20%60RUNNING%60%20and%20imageSha%3A{sha}"
               f"%20and%20lastVmScanDate%3A%5Bnow-{container_scan_days}d%20...%20now%5D")
        tmp = os.path.join(raw_directory, f"_cc_{sha[:12]}_{threading.current_thread().ident}.json")
        code = api_client.make_request(url, tmp)
        count = 0
        if code == 200:
            try: d = json.load(open(tmp)); count = d.get("count", len(d.get("data", [])))
            except: pass
        remove_file_silently(tmp)
        with counter_lock:
            existing_counts[sha] = count; completed += 1
            if completed % 50 == 0 or completed == 1 or completed == len(shas_to_fetch):
                elapsed = time.time() - t0
                rate = elapsed / completed if completed else 1
                logger.info(f"  Containers: {completed}/{len(shas_to_fetch)} ({format_duration(int((len(shas_to_fetch)-completed)*rate))} left)")
            if completed % 100 == 0: write_json_atomically(counts_file, existing_counts)

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as pool:
        futures = {pool.submit(fetch_single, sha): sha for sha in shas_to_fetch}
        for f in concurrent.futures.as_completed(futures):
            check_if_shutdown_requested()
            try: f.result()
            except: pass
    write_json_atomically(counts_file, existing_counts)
    logger.info(f"  Done: {len(shas_to_fetch)} in {format_duration(int(time.time()-t0))}"); return existing_counts

# =============================================================================
# DATA PROCESSING
# =============================================================================
def extract_image_repositories(image_data):
    repo_entries = image_data.get("repo") or []
    digest_entries = image_data.get("repoDigests") or []
    registry_fallback = {d["repository"]: d["registry"] for d in digest_entries
                         if d.get("registry") and d.get("repository")}
    result = []
    for repo in repo_entries:
        registry = repo.get("registry")
        repository = convert_to_safe_string(repo.get("repository"))
        if not registry and repository:
            registry = registry_fallback.get(repository, "")
        result.append({"registry": convert_to_safe_string(registry),
                        "repository": repository,
                        "tag": convert_to_safe_string(repo.get("tag"))})
    return result if result else [{"registry": "", "repository": "", "tag": ""}]

def build_enriched_image_list(raw_images, eol_sha_set, container_counts, skip_containers):
    """Enrich images. EOL is only evaluated when OS is present (not for distroless)."""
    enriched = []
    for image in raw_images:
        image_sha = image.get("sha", "")
        softwares = image.get("softwares") or []
        operating_system = convert_to_safe_string(image.get("operatingSystem"))

        # EOL: only meaningful when OS is known
        if operating_system:
            eol_base_os = image_sha in eol_sha_set
        else:
            eol_base_os = ""  # distroless — cannot evaluate

        enriched.append({
            "image_id":          convert_to_safe_string(image.get("imageId")),
            "image_sha":         image_sha,
            "operating_system":  operating_system,
            "eol_base_os":       eol_base_os,
            "architecture":      convert_to_safe_string(image.get("architecture")),
            "created":           convert_epoch_ms_to_iso(image.get("created")),
            "last_scanned":      convert_epoch_ms_to_iso(image.get("lastScanned")),
            "scan_types":        image.get("scanTypes") or [],
            "source":            image.get("source") or [],
            "repositories":      extract_image_repositories(image),
            "risk_score":        image.get("riskScore"),
            "qds_score":         image.get("maxQdsScore"),
            "qds_severity":      convert_to_safe_string(image.get("qdsSeverity")),
            "container_count":   container_counts.get(image_sha, "N/A") if not skip_containers else "N/A",
            "softwares":         softwares,
        })
    return enriched

# =============================================================================
# CSV REPORT — 25 columns (no vulnerability columns)
#
# One row per (image × repo × software).
# If image has no software → 1 bare row.
# =============================================================================
CSV_HEADERS = [
    # Image columns (17)
    "Image_ID", "Image_SHA", "Operating_System", "EOL_Base_OS", "Architecture",
    "Image_Created", "Image_Last_Scanned", "Image_Scan_Types", "Image_Source",
    "Registry", "Repository", "Image_Tag",
    "Risk_Score", "Max_QDS_Score", "QDS_Severity",
    "Running_Container_Count",

    # Software columns (9)
    "Software_Name", "Software_Installed_Version", "Software_Fix_Version",
    "Software_Package_Path",
    "Software_Lifecycle_Stage", "Software_GA_Date", "Software_EOL_Date", "Software_EOS_Date",
    "Software_Scan_Type",
]

IMAGE_COLUMN_COUNT    = 16
SOFTWARE_COLUMN_COUNT = 9
EMPTY_SOFTWARE_COLS   = [""] * SOFTWARE_COLUMN_COUNT

def build_image_columns(image, repo):
    """Build the 16 image-level columns."""
    return [
        image["image_id"], image["image_sha"],
        image["operating_system"], image["eol_base_os"],
        image["architecture"], image["created"], image["last_scanned"],
        " | ".join(convert_to_safe_string(s) for s in image["scan_types"]),
        " | ".join(convert_to_safe_string(s) for s in image["source"]),
        repo["registry"], repo["repository"], repo["tag"],
        convert_to_safe_string(image["risk_score"]),
        convert_to_safe_string(image["qds_score"]),
        image["qds_severity"],
        image["container_count"],
    ]

def build_software_columns(software):
    """Build the 9 software-level columns."""
    lifecycle = software.get("lifecycle") or {}
    return [
        convert_to_safe_string(software.get("name")),
        convert_to_safe_string(software.get("version")),
        convert_to_safe_string(software.get("fixVersion")),
        convert_to_safe_string(software.get("packagePath")),
        convert_to_safe_string(lifecycle.get("stage")),
        convert_epoch_ms_to_iso(lifecycle.get("gaDate")),
        convert_epoch_ms_to_iso(lifecycle.get("eolDate")),
        convert_epoch_ms_to_iso(lifecycle.get("eosDate")),
        convert_to_safe_string(software.get("scanType")),
    ]

def generate_csv_report(enriched_images, output_path, logger):
    """Write CSV. One row per image × repo × software. No vuln columns."""
    temp_path = output_path + ".tmp"
    total_rows = 0
    with open(temp_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(CSV_HEADERS)
        for image in enriched_images:
            for repo in image["repositories"]:
                image_cols = build_image_columns(image, repo)
                assert len(image_cols) == IMAGE_COLUMN_COUNT

                if image["softwares"]:
                    for sw in image["softwares"]:
                        row = image_cols + build_software_columns(sw)
                        assert len(row) == len(CSV_HEADERS), f"{len(row)} != {len(CSV_HEADERS)}"
                        writer.writerow(row)
                        total_rows += 1
                else:
                    # Bare image — no software
                    row = image_cols + EMPTY_SOFTWARE_COLS
                    assert len(row) == len(CSV_HEADERS)
                    writer.writerow(row)
                    total_rows += 1
    os.replace(temp_path, output_path)
    logger.info(f"  CSV: {output_path} ({total_rows:,} rows)")
    return total_rows

def generate_json_report(enriched_images, output_path, logger):
    write_json_atomically(output_path, {
        "generatedAt": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "totalImages": len(enriched_images),
        "eolImages": sum(1 for img in enriched_images if img["eol_base_os"] is True),
        "images": enriched_images,
    })
    logger.info(f"  JSON: {output_path}")

# =============================================================================
# CLI
# =============================================================================
def parse_command_line_arguments():
    parser = argparse.ArgumentParser(
        prog="qualys_cs_report",
        description=f"Qualys CS Image Report Generator v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Basic — authenticate with username/password
  export QUALYS_USERNAME="myuser"
  export QUALYS_PASSWORD="mypass"
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com

  # Custom filter — only Ubuntu images
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com \\
      -f "operatingSystem:Ubuntu"

  # Skip container counts (faster)
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --skip-containers

  # More threads
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --concurrency 10 --cps 3

  # Dry run
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --dry-run

  # Force fresh
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --force
""",
    )
    env = os.environ.get
    # Authentication (username + password → JWT)
    parser.add_argument("-u", "--username", default=env("QUALYS_USERNAME", ""),
                        help="Qualys username (default: $QUALYS_USERNAME)")
    parser.add_argument("-p", "--password", default=env("QUALYS_PASSWORD", ""),
                        help="Qualys password (default: $QUALYS_PASSWORD)")
    # Connection
    parser.add_argument("-g", "--gateway", default=env("QUALYS_GATEWAY", DEFAULT_GATEWAY))
    # Query
    parser.add_argument("-l", "--limit", type=int, default=int(env("QUALYS_LIMIT", DEFAULT_PAGE_LIMIT)))
    parser.add_argument("-d", "--days", type=int, default=int(env("QUALYS_DAYS", DEFAULT_IMAGE_LOOKBACK_DAYS)))
    parser.add_argument("-D", "--container-scan-days", type=int,
                        default=int(env("QUALYS_CONTAINER_SCAN_DAYS", DEFAULT_CONTAINER_SCAN_DAYS)))
    parser.add_argument("-f", "--filter", default=env("QUALYS_FILTER", ""))
    # Output
    parser.add_argument("-o", "--output-dir", default=env("QUALYS_OUTPUT_DIR", "./qualys_report_output"))
    # Behavior
    parser.add_argument("--skip-containers", action="store_true",
                        default=env("QUALYS_SKIP_CONTAINER_COUNT", "").lower() == "true")
    parser.add_argument("--force", action="store_true")
    # Performance
    parser.add_argument("--concurrency", type=int, default=int(env("QUALYS_CONCURRENCY", DEFAULT_THREAD_COUNT)))
    parser.add_argument("--cps", type=int, default=int(env("QUALYS_CPS", DEFAULT_CALLS_PER_SECOND)))
    parser.add_argument("-r", "--retries", type=int, default=DEFAULT_MAX_RETRIES)
    parser.add_argument("-C", "--curl-extra", default=env("QUALYS_CURL_EXTRA", ""))
    # Output control
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()

# =============================================================================
# MAIN
# =============================================================================
def main():
    args = parse_command_line_arguments()
    start_time = time.time()

    # ── Validate ──
    if not args.username or not args.password:
        print("ERROR: Set QUALYS_USERNAME and QUALYS_PASSWORD, or use -u and -p flags.",
              file=sys.stderr)
        sys.exit(1)
    if not args.gateway.startswith("https://"):
        print("ERROR: Gateway must use HTTPS", file=sys.stderr)
        sys.exit(1)

    # ── Setup ──
    output_dir = args.output_dir
    pages_dir = os.path.join(output_dir, "pages")
    raw_dir = os.path.join(output_dir, "raw")
    os.makedirs(pages_dir, exist_ok=True)
    os.makedirs(raw_dir, exist_ok=True)
    logger, log_file = setup_logging(output_dir, args.verbose, args.quiet)
    acquire_lock_file(output_dir, args.force)

    base_api_url = f"{args.gateway.rstrip('/')}/csapi/{DEFAULT_API_VERSION}"
    image_filter = build_image_api_filter(args.days, args.filter)
    eol_filter = build_image_api_filter(args.days,
        "vulnerabilities.title%3AEOL" + (f"%20and%20{args.filter.replace(' ','%20')}" if args.filter else ""))

    logger.info(f"Qualys CS Report Generator v{VERSION}")
    logger.info(f"Gateway:     {args.gateway}")
    logger.info(f"Username:    {args.username}")
    logger.info(f"Output:      {output_dir}")
    logger.info(f"Params:      limit={args.limit} days={args.days} cdays={args.container_scan_days}")
    logger.info(f"Performance: {args.concurrency} threads, {args.cps} calls/sec, {args.retries} retries")
    if args.filter: logger.info(f"Filter:      {args.filter}")

    if args.dry_run:
        logger.info(f"\nDRY RUN — no API calls")
        logger.info(f"Image URL:     {base_api_url}/images/list?filter={image_filter}&limit={args.limit}")
        logger.info(f"EOL URL:       {base_api_url}/images/list?filter={eol_filter}&limit={args.limit}")
        logger.info(f"Auth URL:      {args.gateway.rstrip('/')}/auth")
        return

    # ── Phase 0: Authenticate ──
    logger.info("\n[Phase 0] Authentication...")
    jwt_token = generate_jwt_token(args.gateway, args.username, args.password,
                                    DEFAULT_CONNECT_TIMEOUT, logger)

    # ── Checkpoint + API client ──
    checkpoint = CheckpointManager(output_dir, generate_config_fingerprint(args))
    if checkpoint.is_phase_complete("complete") and not args.force:
        logger.info("Previous run already complete. Use --force for fresh run.")
        return
    if args.force: checkpoint.clear_all()

    rate_limiter = GlobalRateLimiter(args.cps, logger)
    api_client = QualysApiClient(
        gateway_url=args.gateway, access_token=jwt_token, max_retries=args.retries,
        connect_timeout=DEFAULT_CONNECT_TIMEOUT, request_timeout=DEFAULT_REQUEST_TIMEOUT,
        extra_curl_args=args.curl_extra, rate_limiter=rate_limiter, logger=logger)

    # ── Phase 1: Images ──
    all_images_cache = os.path.join(raw_dir, "all_images.json")
    if checkpoint.is_phase_complete("images"):
        logger.info("\n[Phase 1] Images — cached")
        all_images = json.load(open(all_images_cache))
    else:
        logger.info("\n[Phase 1] Fetching images...")
        image_url = f"{base_api_url}/images/list?filter={image_filter}&limit={args.limit}"
        all_images = api_client.fetch_all_pages(image_url, pages_dir, "img", args.limit)
        write_json_atomically(all_images_cache, all_images)
        checkpoint.mark_complete("images")
    logger.info(f"  Total: {len(all_images)} images")
    if not all_images: logger.warning("  WARNING: 0 images returned.")

    # ── Phase 2: EOL ──
    eol_cache = os.path.join(raw_dir, "eol_shas.json")
    if checkpoint.is_phase_complete("eol"):
        logger.info("\n[Phase 2] EOL — cached")
        eol_image_shas = set(json.load(open(eol_cache)))
    else:
        logger.info("\n[Phase 2] Fetching EOL images...")
        eol_url = f"{base_api_url}/images/list?filter={eol_filter}&limit={args.limit}"
        eol_images = api_client.fetch_all_pages(eol_url, pages_dir, "eol", args.limit)
        eol_image_shas = set(img["sha"] for img in eol_images if img.get("sha"))
        write_json_atomically(eol_cache, list(eol_image_shas))
        checkpoint.mark_complete("eol")
    logger.info(f"  EOL: {len(eol_image_shas)}")

    # ── Phase 3: Container counts ──
    container_counts = {}
    if args.skip_containers:
        logger.info("\n[Phase 3] Containers — skipped")
    elif checkpoint.is_phase_complete("containers"):
        logger.info("\n[Phase 3] Containers — cached")
        container_counts = json.load(open(os.path.join(raw_dir, "container_counts.json")))
    else:
        logger.info("\n[Phase 3] Fetching container counts...")
        unique_shas = list(set(img["sha"] for img in all_images if img.get("sha")))
        cc_file = os.path.join(raw_dir, "container_counts.json")
        if os.path.exists(cc_file):
            try: container_counts = json.load(open(cc_file))
            except: container_counts = {}
        container_counts = fetch_container_counts_parallel(
            api_client, base_api_url, unique_shas, args.container_scan_days,
            container_counts, raw_dir, args.concurrency, logger)
        checkpoint.mark_complete("containers")

    # ── Phase 4: Reports ──
    logger.info("\n[Phase 4] Reports...")
    enriched = build_enriched_image_list(all_images, eol_image_shas, container_counts, args.skip_containers)
    csv_rows = generate_csv_report(enriched, os.path.join(output_dir, "qualys_cs_unified_report.csv"), logger)
    generate_json_report(enriched, os.path.join(output_dir, "images_full_report.json"), logger)

    # ── Phase 5: Summary ──
    total_duration = int(time.time() - start_time)
    summary = {
        "version": VERSION,
        "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gateway": args.gateway, "username": args.username,
        "total_images": len(enriched),
        "unique_images": len(set(img["image_sha"] for img in enriched)),
        "eol_images": sum(1 for img in enriched if img["eol_base_os"] is True),
        "csv_rows": csv_rows, "csv_columns": len(CSV_HEADERS),
        "duration": format_duration(total_duration),
        "api_calls": api_client.total_api_calls,
        "retries": api_client.total_retries,
        "errors": api_client.total_errors,
        "throttles": rate_limiter.total_throttle_events,
        "concurrency": args.concurrency, "cps": args.cps,
    }
    write_json_atomically(os.path.join(output_dir, "run_summary.json"), summary)
    checkpoint.mark_complete("complete")

    logger.info(f"\n{'='*55}")
    logger.info(f"  DONE in {format_duration(total_duration)}")
    logger.info(f"  Images: {summary['total_images']} | EOL: {summary['eol_images']}")
    logger.info(f"  CSV: {csv_rows:,} rows × {len(CSV_HEADERS)} cols | API: {api_client.total_api_calls} calls")
    logger.info(f"  Output: {output_dir}/")
    logger.info(f"{'='*55}")

if __name__ == "__main__":
    main()
