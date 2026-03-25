#!/usr/bin/env python3
"""
Qualys Container Security — Image Report Generator
====================================================

What this script does (5 phases):
  Phase 1: Calls Qualys Image Bulk API to get all container images in use
  Phase 2: Calls Qualys Image Bulk API with EOL filter to find images running
           end-of-life base OS. Compares SHAs: match = EOL_Base_OS = True
  Phase 3: For each unique image SHA, calls Container API to get the count
           of running containers (blast radius)
  Phase 4: Combines everything into a single denormalized CSV + JSON report
  Phase 5: Writes a run summary with stats

Idempotent: re-run safely — completed phases are skipped, partial work resumes.
             Use --force to start fresh.

Prerequisites: Python 3.8+, curl (no pip packages needed)
"""

import argparse
import atexit
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
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# Default configuration — all overridable via CLI flags or env vars
# ---------------------------------------------------------------------------
DEFAULTS = {
    "gateway":             "https://gateway.qg2.apps.qualys.com",
    "api_version":         "v1.3",
    "limit":               250,   # max records per API page (Qualys max is 250)
    "days":                30,    # fetch images used in the last N days
    "container_scan_days": 3,     # container scan lookback for running count
    "retries":             5,     # max retries per failed API call
    "connect_timeout":     30,    # curl connect timeout (seconds)
    "request_timeout":     300,   # curl max request time (seconds)
    "rl_floor":            10,    # start throttling when remaining calls <= this
    "rl_pause":            3,     # seconds to pause when near rate limit
    "rl_buffer":           5,     # extra seconds to wait after rate limit window resets
}

# ---------------------------------------------------------------------------
# Signal handling — Ctrl+C / kill saves state cleanly instead of crashing
# ---------------------------------------------------------------------------
_shutdown = False

def _on_signal(sig, _):
    """Catch SIGINT (Ctrl+C) and SIGTERM (kill) to exit gracefully."""
    global _shutdown
    print(f"\n[!] {signal.Signals(sig).name} — saving state...", file=sys.stderr)
    _shutdown = True

signal.signal(signal.SIGINT, _on_signal)
signal.signal(signal.SIGTERM, _on_signal)

def _check_shutdown():
    """Called in loops — if signal received, exit with code 130 (resume later)."""
    if _shutdown:
        raise SystemExit(130)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def safe(val) -> str:
    """Convert None or the literal string 'None' (which Qualys API sometimes
    returns instead of null) to empty string. Everything else → str."""
    if val is None or val == "None":
        return ""
    return str(val)

def epoch_to_iso(val) -> str:
    """Convert Qualys epoch-milliseconds timestamp to ISO 8601 string.
    Example: 1774303950426 → '2026-03-23T22:12:30Z'
    Returns empty string for null/zero values."""
    if not val or str(val) == "0":
        return ""
    try:
        return datetime.fromtimestamp(int(val) / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return str(val)

def atomic_write_json(path: str, data):
    """Write JSON to a temp file first, then atomically rename into place.
    This prevents corrupt files if the script crashes mid-write."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, path)  # atomic on same filesystem
    except Exception:
        try: os.remove(tmp)
        except OSError: pass
        raise

def fmt_duration(s: int) -> str:
    """Format seconds into human-readable duration: 45s, 3m12s, 1h5m."""
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s//60}m{s%60}s"
    return f"{s//3600}h{(s%3600)//60}m"

def _rm(path):
    """Silently remove a file (no error if missing)."""
    try: os.remove(path)
    except OSError: pass

def config_fingerprint(args) -> str:
    """Generate a short hash of all config that affects API data.
    If the user changes --days, --filter, etc., the checkpoint auto-resets
    so stale cached data isn't mixed with new parameters."""
    key = (f"{args.gateway}|{args.days}|{args.container_scan_days}"
           f"|{args.limit}|{args.skip_containers}|{args.filter or ''}")
    return hashlib.sha256(key.encode()).hexdigest()[:16]

def build_image_filter(days: int, extra_filter: str = "") -> str:
    """Build the URL-encoded filter string for the Image List API.
    Base filter: imagesInUse:[now-Nd ... now]
    If extra_filter is provided (e.g. 'operatingSystem:Ubuntu'), it's
    appended with AND."""
    base = f"imagesInUse%3A%60%5Bnow-{days}d%20...%20now%5D%60"
    if extra_filter:
        encoded = extra_filter.replace(" ", "%20")
        base = f"{base}%20and%20{encoded}"
    return base

# ---------------------------------------------------------------------------
# Logging — writes to both console and a log file
# ---------------------------------------------------------------------------
def setup_logging(output_dir: str, verbose: bool, quiet: bool):
    log = logging.getLogger("qualys")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()

    # Log file — always captures everything (DEBUG level)
    log_file = os.path.join(output_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    log.addHandler(fh)

    # Console — INFO by default, DEBUG if --verbose, nothing if --quiet
    if not quiet:
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG if verbose else logging.INFO)
        ch.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(ch)

    return log, log_file

# ---------------------------------------------------------------------------
# Lock file — prevents two runs from writing to the same output directory
# ---------------------------------------------------------------------------
def acquire_lock(output_dir: str, force: bool):
    """Create a .lock file with our PID. If another instance is running
    (PID is alive), refuse to start unless --force is used."""
    lock = os.path.join(output_dir, ".lock")
    if os.path.exists(lock):
        try:
            pid = int(open(lock).read().strip())
            os.kill(pid, 0)  # check if process is alive (doesn't kill it)
            if not force:
                print(f"ERROR: Another instance running (PID {pid}). Use --force.", file=sys.stderr)
                sys.exit(1)
        except (ValueError, ProcessLookupError, PermissionError):
            pass  # stale lock from a dead process — safe to override
    open(lock, "w").write(str(os.getpid()))
    atexit.register(lambda: _rm(lock))  # auto-cleanup on exit

# ---------------------------------------------------------------------------
# Checkpoint — enables idempotent resume across script restarts
# ---------------------------------------------------------------------------
class Checkpoint:
    """Tracks which phases are done. Saved to disk as JSON.
    On re-run: completed phases are skipped.
    If config changes (different fingerprint), checkpoint auto-resets."""

    def __init__(self, output_dir: str, fingerprint: str):
        self.path = os.path.join(output_dir, ".checkpoint.json")
        self.fingerprint = fingerprint
        self.data = {}
        if os.path.exists(self.path):
            try:
                self.data = json.load(open(self.path))
                if self.data.get("fingerprint") != fingerprint:
                    self.data = {}  # config changed — start fresh
            except (json.JSONDecodeError, KeyError):
                self.data = {}

    def done(self, phase: str) -> bool:
        return self.data.get(phase) is True

    def mark(self, phase: str):
        """Mark a phase as complete and save to disk."""
        self.data[phase] = True
        self.data["fingerprint"] = self.fingerprint
        atomic_write_json(self.path, self.data)

    def clear(self):
        _rm(self.path)
        self.data = {}

# ---------------------------------------------------------------------------
# Rate limiter — reads Qualys API rate-limit headers, throttles proactively
#
# Qualys returns these headers on every response:
#   X-RateLimit-Remaining: calls left in current window
#   X-RateLimit-Window-Sec: window duration in seconds
#   Retry-After: seconds to wait (only on HTTP 429)
#
# Strategy:
#   remaining > floor (10)  → continue normally
#   remaining ≤ floor (10)  → pause 3s (proactive throttle)
#   remaining = 0           → wait for window reset + 5s buffer
#   HTTP 429                → honour Retry-After header
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, floor, pause, buffer, log):
        self.floor = floor      # start throttling below this
        self.pause = pause      # seconds to pause when near limit
        self.buffer = buffer    # extra seconds after window reset
        self.log = log
        self.remaining = None   # last known remaining calls
        self.window = None      # last known window duration
        self.waits = 0          # total number of throttle events
        self.wait_secs = 0      # total seconds spent waiting

    def read_headers(self, header_file: str):
        """Parse rate-limit headers from curl's -D dump file."""
        if not os.path.exists(header_file):
            return
        try:
            for line in open(header_file):
                lo = line.lower().strip()
                if lo.startswith("x-ratelimit-remaining:"):
                    self.remaining = int(line.split(":", 1)[1].strip())
                elif lo.startswith("x-ratelimit-window-sec:"):
                    self.window = int(line.split(":", 1)[1].strip())
        except (ValueError, IOError):
            return

        # Proactive throttle based on remaining calls
        if self.remaining is not None:
            if self.remaining <= 0:
                self._wait((self.window or 60) + self.buffer, "rate limit exhausted")
            elif self.remaining <= self.floor:
                self._wait(self.pause, f"rate limit low ({self.remaining} left)")

    def handle_429(self, header_file: str):
        """Handle HTTP 429 (Too Many Requests)."""
        ra = None
        if os.path.exists(header_file):
            try:
                for line in open(header_file):
                    if line.lower().strip().startswith("retry-after:"):
                        ra = int(line.split(":", 1)[1].strip())
            except (ValueError, IOError):
                pass
        # Use Retry-After if available, otherwise wait for window reset
        self._wait(ra or (self.window or 30) + self.buffer, "HTTP 429")

    def _wait(self, secs: int, reason: str):
        self.log.warning(f"  Throttle: {reason} — waiting {secs}s")
        self.waits += 1
        self.wait_secs += secs
        time.sleep(secs)

# ---------------------------------------------------------------------------
# API client — handles all Qualys CSAPI HTTP interactions
#
# Features:
#   - Retries with exponential backoff + jitter (no thundering herd)
#   - Classifies errors: fatal (401/403/404) vs transient (429/5xx/timeout)
#   - Pagination via Link header with crash-safe resume
# ---------------------------------------------------------------------------
class APIClient:
    def __init__(self, gateway, token, api_ver, retries, conn_timeout,
                 req_timeout, curl_extra, rate_limiter, log):
        self.gw = gateway.rstrip("/")
        self.token = token
        self.api = api_ver
        self.retries = retries
        self.conn_to = conn_timeout
        self.req_to = req_timeout
        self.curl_extra = curl_extra
        self.rl = rate_limiter
        self.log = log
        self.calls = 0          # total API calls made
        self.retries_used = 0   # total retry attempts
        self.errors = 0         # total non-200 responses

    def _backoff(self, attempt: int) -> float:
        """Exponential backoff with full jitter: random(0, min(120, 2^attempt)).
        This prevents multiple instances from retrying at the exact same time."""
        return random.uniform(0, min(120, 2 ** attempt))

    def get(self, url: str, out_file: str, keep_headers: bool = False) -> bool:
        """Make a GET request with retry logic. Returns True on HTTP 200.

        Args:
            url: The full API URL to call
            out_file: Where to save the response body
            keep_headers: If True, keep the .hdr file (needed for pagination
                          to extract the Link header for the next page)
        """
        for attempt in range(self.retries + 1):
            _check_shutdown()

            # Wait before retries (not on first attempt)
            if attempt > 0:
                delay = self._backoff(attempt)
                self.log.warning(f"  Retry {attempt}/{self.retries} in {delay:.0f}s")
                time.sleep(delay)
                self.retries_used += 1

            # Build and execute curl command
            hdr_file = out_file + ".hdr"
            cmd = ["curl", "-s",
                   "-o", out_file,       # save response body
                   "-D", hdr_file,       # save response headers
                   "-w", "%{http_code}", # print HTTP status code to stdout
                   "--connect-timeout", str(self.conn_to),
                   "--max-time", str(self.req_to),
                   "-X", "GET", url,
                   "-H", "Accept: application/json",
                   "-H", f"Authorization: Bearer {self.token}"]
            if self.curl_extra:
                cmd.extend(self.curl_extra.split())

            try:
                r = subprocess.run(cmd, capture_output=True, text=True)
                code = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
            except Exception as e:
                self.log.warning(f"  curl error: {e}")
                self.errors += 1
                continue
            finally:
                self.calls += 1

            # Always check rate-limit headers (even on errors)
            self.rl.read_headers(hdr_file)

            # Handle response codes
            if code == 200:
                if not keep_headers:
                    _rm(hdr_file)
                return True

            # Fatal errors — no point retrying
            if code == 401:
                self.log.error("HTTP 401 — token expired or invalid"); sys.exit(1)
            if code == 403:
                self.log.error("HTTP 403 — insufficient permissions"); sys.exit(1)
            if code == 404:
                self.log.error(f"HTTP 404 — not found: {url}"); sys.exit(1)

            # Transient errors — retry
            if code == 429:
                self.rl.handle_429(hdr_file)
            else:
                self.log.warning(f"  HTTP {code}")
            _rm(hdr_file)
            self.errors += 1

        self.log.error(f"  Failed after {self.retries} retries: {url}")
        return False

    def get_all_pages(self, url: str, pages_dir: str, label: str,
                      page_size: int) -> List[Dict]:
        """Fetch ALL pages from a paginated Qualys API endpoint.

        How Qualys pagination works:
          - Response header: Link: <next_url>;rel=next (if more pages exist)
          - No Link header = this is the last page
          - page_size (--limit) is used to detect "full" vs "partial" pages

        Resume/crash safety:
          - Each page is saved to disk as {label}_{page}.json
          - The .hdr file (containing Link header) is kept until the NEXT page
            is successfully saved — so we never lose the "next" URL
          - If .hdr is missing on a full cached page, we re-fetch that page
            to recover the Link header and continue
        """
        result = []
        page = 1

        while url:
            _check_shutdown()
            pf = os.path.join(pages_dir, f"{label}_{page:04d}.json")
            hdr = pf + ".hdr"

            # ── Try to reuse a previously cached page ──
            if os.path.exists(pf):
                try:
                    data = json.load(open(pf)).get("data", [])
                except (json.JSONDecodeError, KeyError, TypeError):
                    data = None  # corrupted cache — re-fetch below

                if isinstance(data, list) and len(data) > 0:
                    nxt = self._next_url(hdr)
                    if nxt:
                        # Cached page + Link header → skip to next page
                        result.extend(data)
                        self.log.info(f"  {label} p{page}: {len(data)} records (cached)")
                        url = nxt
                        page += 1
                        continue
                    elif len(data) < page_size:
                        # Cached partial page = last page — we're done
                        result.extend(data)
                        self.log.info(f"  {label} p{page}: {len(data)} records (cached, last page)")
                        break
                    else:
                        # Full page but .hdr file is missing (crash between saves)
                        # Must re-fetch to recover the Link header
                        self.log.info(f"  {label} p{page}: cached but Link header lost — re-fetching")
                else:
                    self.log.debug(f"  {label} p{page}: cached page empty/corrupt — re-fetching")

            # ── Fresh fetch from API ──
            self.log.info(f"  Fetching {label} page {page}...")
            if not self.get(url, pf, keep_headers=True):
                self.log.error(f"  Failed on {label} page {page}")
                break

            # Parse and validate the response JSON
            try:
                data = json.load(open(pf)).get("data", [])
                if not isinstance(data, list):
                    self.log.warning(f"  {label} p{page}: 'data' is not a list")
                    break
            except (json.JSONDecodeError, KeyError, TypeError):
                self.log.warning(f"  {label} p{page}: bad JSON")
                break

            result.extend(data)
            self.log.info(f"  {label} p{page}: {len(data)} records (total: {len(result)})")

            # ── Determine next page ──
            nxt = self._next_url(hdr)
            if nxt:
                # More pages exist — clean up PREVIOUS page's .hdr
                # (current page's .hdr stays for crash recovery)
                if page > 1:
                    prev_hdr = os.path.join(pages_dir, f"{label}_{page-1:04d}.json.hdr")
                    _rm(prev_hdr)
                url = nxt
                page += 1
            elif len(data) < page_size:
                # Fewer records than limit = last page
                _rm(hdr)
                break
            else:
                # Full page + no Link header = Qualys says done
                _rm(hdr)
                break

        # Clean up last .hdr file
        _rm(os.path.join(pages_dir, f"{label}_{page:04d}.json.hdr"))
        self.log.info(f"  {label} total: {len(result)} records across {page} pages")
        return result

    @staticmethod
    def _next_url(hdr_file: str) -> str:
        """Extract the next page URL from the Link response header.
        Format: Link: <https://...>;rel=next"""
        if not os.path.exists(hdr_file):
            return ""
        try:
            for line in open(hdr_file):
                if line.lower().startswith("link:"):
                    m = re.search(r'<([^>]+)>;rel=next', line)
                    if m:
                        return m.group(1)
        except Exception:
            pass
        return ""

# ---------------------------------------------------------------------------
# Data processing — extract and transform raw API data into report-ready form
# ---------------------------------------------------------------------------
def extract_repos(img: Dict) -> List[Dict]:
    """Extract all (registry, repository, tag) entries from an image.

    Some images have multiple repos (e.g. pushed to both docker.io and ECR).
    Each repo becomes a separate row in the CSV for clean Excel filtering.

    Falls back to repoDigests for registry when repo.registry is null."""
    repos = img.get("repo") or []
    digests = img.get("repoDigests") or []

    # Build fallback lookup: repository → registry from repoDigests
    fallback = {d["repository"]: d["registry"] for d in digests
                if d.get("registry") and d.get("repository")}

    out = []
    for r in repos:
        reg = r.get("registry")
        repo = safe(r.get("repository"))
        # If registry is null, try to find it from repoDigests
        if not reg and repo:
            reg = fallback.get(repo, "")
        out.append({"registry": safe(reg), "repository": repo, "tag": safe(r.get("tag"))})

    # If no repos at all, return one empty entry so the image still gets a row
    return out or [{"registry": "", "repository": "", "tag": ""}]


def enrich(images, eol_shas, container_counts, skip_containers):
    """Transform raw Qualys API image records into enriched report records.

    Adds:
      - eol: True if this image's SHA was returned by the EOL-filtered API call
      - containers: running container count from Container API (or N/A if skipped)
    """
    out = []
    for img in images:
        sha = img.get("sha", "")
        vulns = img.get("vulnerabilities") or []
        sws = img.get("softwares") or []
        out.append({
            "imageId":    safe(img.get("imageId")),
            "sha":        sha,
            "os":         safe(img.get("operatingSystem")),
            "eol":        sha in eol_shas,  # True if SHA matched EOL API response
            "arch":       safe(img.get("architecture")),
            "created":    epoch_to_iso(img.get("created")),
            "scanned":    epoch_to_iso(img.get("lastScanned")),
            "scanTypes":  img.get("scanTypes") or [],
            "repos":      extract_repos(img),
            "risk":       img.get("riskScore"),
            "qds":        img.get("maxQdsScore"),
            "severity":   safe(img.get("qdsSeverity")),
            "vulnCount":  len(vulns),
            "containers": container_counts.get(sha, "N/A") if not skip_containers else "N/A",
            "vulns":      vulns,
            "sws":        sws,
        })
    return out

# ---------------------------------------------------------------------------
# CSV report generation — 28 columns, fully denormalized
#
# Row generation logic (for each image × each registry/repo/tag):
#
#   Pass 1 — VULNERABILITY ROWS (primary):
#     Each vulnerability lists 1+ affected softwares. We write one row per
#     (vuln × affected_software). If the affected software matches an
#     installed package (by name+version), the Software_* columns are filled.
#
#   Pass 2 — SOFTWARE-ONLY ROWS:
#     Installed packages NOT already written via a vulnerability get their own
#     row. Vuln columns are blank.
#
#   Pass 3 — BARE IMAGE ROW:
#     Images with zero software and zero vulns still get 1 row.
# ---------------------------------------------------------------------------

# Column definitions — order matters (must match row builder functions)
HEADERS = [
    # Image-level columns (16)
    "Image_ID", "Image_SHA", "Operating_System", "EOL_Base_OS", "Architecture",
    "Image_Created", "Image_Last_Scanned", "Image_Scan_Types",
    "Registry", "Repository", "Image_Tag",
    "Risk_Score", "Max_QDS_Score", "QDS_Severity",
    "Total_Vulnerabilities_On_Image", "Running_Container_Count",
    # Software-level columns (5)
    "Software_Name", "Software_Installed_Version", "Software_Fix_Version",
    "Software_Lifecycle_Stage", "Software_EOL_Date",
    # Vulnerability-level columns (7)
    "Vuln_QID", "Vuln_Scan_Type", "Vuln_Type_Detected", "Vuln_First_Found",
    "Vuln_Affected_Software_Name", "Vuln_Affected_Software_Version", "Vuln_Fix_Version",
]

# Column counts (used for assertions and empty-column generation)
N_IMG = 16; N_SW = 5; N_VLN = 7
EMPTY_SW = [""] * N_SW    # blank software columns for non-sw rows
EMPTY_VLN = [""] * N_VLN  # blank vuln columns for non-vuln rows


def _img_row(img, repo):
    """Build the 16 image-level columns for one row."""
    return [
        img["imageId"], img["sha"], img["os"], img["eol"], img["arch"],
        img["created"], img["scanned"],
        " | ".join(safe(s) for s in img["scanTypes"]),  # e.g. "SCA | STATIC"
        repo["registry"], repo["repository"], repo["tag"],
        safe(img["risk"]), safe(img["qds"]), img["severity"],
        img["vulnCount"], img["containers"],
    ]

def _sw_row(sw):
    """Build the 5 software-level columns for one installed package."""
    lc = sw.get("lifecycle") or {}
    return [
        safe(sw.get("name")),
        safe(sw.get("version")),
        safe(sw.get("fixVersion")),
        safe(lc.get("stage")),            # e.g. "EOL/EOS", "GA"
        epoch_to_iso(lc.get("eolDate")),  # end-of-life date
    ]

def _vln_row(v, vsw):
    """Build the 7 vulnerability-level columns for one QID × affected software."""
    return [
        safe(v.get("qid")),
        " | ".join(safe(s) for s in (v.get("scanType") or [])),  # e.g. "SCA"
        safe(v.get("typeDetected")),                               # CONFIRMED / POTENTIAL
        epoch_to_iso(v.get("firstFound")),
        safe(vsw.get("name")),       # affected software name
        safe(vsw.get("version")),    # affected software version
        safe(vsw.get("fixVersion")), # version that fixes the vuln
    ]


def write_csv(images, path, log):
    """Write the unified CSV report. Uses atomic write (temp → rename)."""
    tmp = path + ".tmp"
    n = 0
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(HEADERS)

        for img in images:
            # Build software lookup ONCE per image (not per repo)
            # Key: (name, version) → software dict
            sw_map = {(safe(s.get("name")), safe(s.get("version"))): s
                      for s in img["sws"]}
            vulns = img["vulns"]
            sws = img["sws"]

            # Each repo entry generates its own set of rows
            # (so multi-registry images get separate rows per registry)
            for repo in img["repos"]:
                base = _img_row(img, repo)
                assert len(base) == N_IMG  # column count safety check

                sw_done = set()  # track which software was covered by vuln rows

                # Pass 1: Vulnerability rows
                for v in vulns:
                    # Each vuln may affect 1+ softwares
                    # If software list is null/empty, we still write 1 row with blank sw
                    for vsw in (v.get("software") or [{}]):
                        k = (safe(vsw.get("name")), safe(vsw.get("version")))
                        matched = sw_map.get(k)  # try to match vuln sw → installed sw
                        row = base + (_sw_row(matched) if matched else EMPTY_SW) + _vln_row(v, vsw)
                        assert len(row) == len(HEADERS)
                        w.writerow(row)
                        n += 1
                        if matched:
                            sw_done.add(k)

                # Pass 2: Software-only rows (not already written via vulns)
                for sw in sws:
                    k = (safe(sw.get("name")), safe(sw.get("version")))
                    if k not in sw_done:
                        row = base + _sw_row(sw) + EMPTY_VLN
                        assert len(row) == len(HEADERS)
                        w.writerow(row)
                        n += 1

                # Pass 3: Bare image (no software, no vulns)
                if not sws and not vulns:
                    row = base + EMPTY_SW + EMPTY_VLN
                    assert len(row) == len(HEADERS)
                    w.writerow(row)
                    n += 1

    os.replace(tmp, path)  # atomic rename
    log.info(f"  CSV: {path} ({n:,} rows)")
    return n


def write_json(images, path, log):
    """Write the full JSON report (all enriched data)."""
    atomic_write_json(path, {
        "generatedAt": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "totalImages": len(images),
        "eolImages": sum(1 for i in images if i["eol"]),
        "images": images,
    })
    log.info(f"  JSON: {path}")

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        prog="qualys_cs_report",
        description=f"Qualys CS Image Report Generator v{VERSION}",
        epilog="""
examples:
  # Basic — images in use last 30 days
  export QUALYS_ACCESS_TOKEN="eyJ..."
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com

  # Custom filter — only Ubuntu images
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com \\
      -f "operatingSystem:Ubuntu"

  # Custom filter — specific registry
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com \\
      -f "repo.registry:docker.io"

  # Fast run — skip container counts
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --skip-containers

  # Dry run — show config, no API calls
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --dry-run

  # Force fresh (ignore checkpoint)
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --force
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    D = DEFAULTS
    env = os.environ.get
    p.add_argument("-g", "--gateway",    default=env("QUALYS_GATEWAY", D["gateway"]),   help="Qualys gateway URL")
    p.add_argument("-t", "--token",      default=env("QUALYS_ACCESS_TOKEN", ""),         help="Bearer token (default: $QUALYS_ACCESS_TOKEN)")
    p.add_argument("-l", "--limit",      type=int, default=int(env("QUALYS_LIMIT", D["limit"])),  help="Results per page, 1-250")
    p.add_argument("-d", "--days",       type=int, default=int(env("QUALYS_DAYS", D["days"])),      help="Image lookback days")
    p.add_argument("-D", "--container-scan-days", type=int, default=int(env("QUALYS_CONTAINER_SCAN_DAYS", D["container_scan_days"])), help="Container scan lookback days")
    p.add_argument("-f", "--filter",     default=env("QUALYS_FILTER", ""),    help="Extra filter appended with AND (e.g. 'operatingSystem:Ubuntu')")
    p.add_argument("-o", "--output-dir", default=env("QUALYS_OUTPUT_DIR", "./qualys_report_output"), help="Output directory")
    p.add_argument("--skip-containers",  action="store_true", default=env("QUALYS_SKIP_CONTAINER_COUNT", "").lower() == "true", help="Skip container count API calls (faster)")
    p.add_argument("--force",            action="store_true",  help="Ignore checkpoint, start fresh")
    p.add_argument("-r", "--retries",    type=int, default=D["retries"],      help="Max retries per API call")
    p.add_argument("-C", "--curl-extra", default=env("QUALYS_CURL_EXTRA", ""),help="Extra curl arguments (e.g. '--proxy http://proxy:8080')")
    p.add_argument("-v", "--verbose",    action="store_true",  help="Debug output")
    p.add_argument("-q", "--quiet",      action="store_true",  help="Suppress console output")
    p.add_argument("--dry-run",          action="store_true",  help="Show config and URLs, no API calls")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main orchestrator — runs all 5 phases
# ---------------------------------------------------------------------------
def main():
    args = parse_args()
    t0 = time.time()

    # ── Input validation ──
    if not args.token:
        print("ERROR: Set QUALYS_ACCESS_TOKEN or use -t <token>", file=sys.stderr)
        sys.exit(1)
    if not args.gateway.startswith("https://"):
        print("ERROR: Gateway must use HTTPS", file=sys.stderr)
        sys.exit(1)
    if not 1 <= args.limit <= 250:
        print(f"ERROR: --limit must be 1-250, got {args.limit}", file=sys.stderr)
        sys.exit(1)

    # ── Setup output directories, logging, lock file ──
    od = args.output_dir
    pages_dir = os.path.join(od, "pages")
    raw_dir = os.path.join(od, "raw")
    os.makedirs(pages_dir, exist_ok=True)
    os.makedirs(raw_dir, exist_ok=True)
    log, log_file = setup_logging(od, args.verbose, args.quiet)
    acquire_lock(od, args.force)

    # ── Build API URLs ──
    base_url = f"{args.gateway.rstrip('/')}/csapi/{DEFAULTS['api_version']}"

    # Image filter: imagesInUse:[now-Nd ... now] AND (optional user filter)
    img_filter = build_image_filter(args.days, args.filter)
    # EOL filter: same + vulnerabilities.title:EOL
    eol_filter = build_image_filter(args.days,
        f"vulnerabilities.title%3AEOL" + (f"%20and%20{args.filter.replace(' ', '%20')}" if args.filter else ""))

    img_url = f"{base_url}/images/list?filter={img_filter}&limit={args.limit}"
    eol_url = f"{base_url}/images/list?filter={eol_filter}&limit={args.limit}"

    log.info(f"Qualys CS Report Generator v{VERSION}")
    log.info(f"Gateway:  {args.gateway}")
    log.info(f"Output:   {od}")
    log.info(f"Params:   limit={args.limit} days={args.days} container_days={args.container_scan_days}")
    if args.filter:
        log.info(f"Filter:   {args.filter}")

    # ── Dry run — show config and exit ──
    if args.dry_run:
        log.info(f"\nDRY RUN — no API calls")
        log.info(f"Token:         {args.token[:10]}...{args.token[-6:]}")
        log.info(f"Image URL:     {img_url}")
        log.info(f"EOL URL:       {eol_url}")
        log.info(f"Container URL: {base_url}/containers?filter=state%3A%60RUNNING%60%20and%20imageSha%3A<SHA>%20and%20lastVmScanDate%3A%5Bnow-{args.container_scan_days}d%20...%20now%5D")
        return

    # ── Checkpoint — enables idempotent resume ──
    chk = Checkpoint(od, config_fingerprint(args))
    if chk.done("complete") and not args.force:
        log.info("Previous run already complete. Use --force for fresh run.")
        return
    if args.force:
        chk.clear()

    # ── Create API client with rate limiter ──
    rl = RateLimiter(DEFAULTS["rl_floor"], DEFAULTS["rl_pause"], DEFAULTS["rl_buffer"], log)
    api = APIClient(args.gateway, args.token, DEFAULTS["api_version"],
                    args.retries, DEFAULTS["connect_timeout"], DEFAULTS["request_timeout"],
                    args.curl_extra, rl, log)

    # ==================================================================
    # PHASE 1: Fetch all images from Image Bulk API
    # API: GET /images/list?filter=imagesInUse:[now-Nd...now]&limit=250
    # Paginates via Link header until all images are fetched
    # ==================================================================
    img_file = os.path.join(raw_dir, "all_images.json")
    if chk.done("images"):
        log.info("\n[Phase 1] Images — cached")
        images = json.load(open(img_file))
    else:
        log.info("\n[Phase 1] Fetching images...")
        images = api.get_all_pages(img_url, pages_dir, "img", args.limit)
        atomic_write_json(img_file, images)
        chk.mark("images")  # checkpoint: Phase 1 done
    log.info(f"  Total: {len(images)} images")

    if len(images) == 0:
        log.warning("  WARNING: 0 images returned. Check gateway, token, and filter.")
        log.warning(f"  URL: {img_url}")

    # ==================================================================
    # PHASE 2: Fetch EOL images (for EOL_Base_OS column)
    # API: GET /images/list?filter=imagesInUse:... AND vulnerabilities.title:EOL
    # This returns ONLY images where Qualys has flagged an EOL vulnerability.
    # We collect their SHAs and compare against Phase 1 SHAs:
    #   SHA in both → EOL_Base_OS = True
    #   SHA only in Phase 1 → EOL_Base_OS = False
    # ==================================================================
    eol_file = os.path.join(raw_dir, "eol_shas.json")
    if chk.done("eol"):
        log.info("\n[Phase 2] EOL images — cached")
        eol_shas = set(json.load(open(eol_file)))
    else:
        log.info("\n[Phase 2] Fetching EOL images...")
        eol_imgs = api.get_all_pages(eol_url, pages_dir, "eol", args.limit)
        eol_shas = set(i["sha"] for i in eol_imgs if i.get("sha"))
        atomic_write_json(eol_file, list(eol_shas))
        chk.mark("eol")  # checkpoint: Phase 2 done
    log.info(f"  EOL images: {len(eol_shas)}")

    # ==================================================================
    # PHASE 3: Fetch running container count per image SHA
    # API: GET /containers?filter=state:RUNNING AND imageSha:<SHA>
    #          AND lastVmScanDate:[now-3d...now]
    # Makes 1 API call per unique SHA. Checkpoints every 50 SHAs.
    # Skip with --skip-containers for faster runs.
    # ==================================================================
    cc_file = os.path.join(raw_dir, "container_counts.json")
    cc: Dict[str, int] = {}
    if args.skip_containers:
        log.info("\n[Phase 3] Container counts — skipped")
    elif chk.done("containers"):
        log.info("\n[Phase 3] Container counts — cached")
        cc = json.load(open(cc_file))
    else:
        log.info("\n[Phase 3] Fetching container counts...")
        shas = list(set(i["sha"] for i in images if i.get("sha")))
        total = len(shas)
        log.info(f"  {total} unique image SHAs to query")

        # Resume partial progress (if script was interrupted mid-phase)
        if os.path.exists(cc_file):
            try:
                cc = json.load(open(cc_file))
                log.info(f"  Resuming: {len(cc)} already fetched")
            except (json.JSONDecodeError, KeyError):
                cc = {}

        t_start = time.time()
        fetched = 0
        for i, sha in enumerate(shas, 1):
            _check_shutdown()

            # Skip SHAs already fetched (resume support)
            if sha in cc:
                continue
            fetched += 1

            # Progress log with ETA every 25 SHAs
            if fetched == 1 or fetched % 25 == 0:
                if fetched > 1:
                    rate = (time.time() - t_start) / fetched
                    eta = fmt_duration(int((total - i) * rate))
                else:
                    eta = "calculating..."
                log.info(f"  {i}/{total} (ETA: {eta})")

            # Build container API URL for this image SHA
            url = (f"{base_url}/containers"
                   f"?filter=state%3A%20%60RUNNING%60%20and%20imageSha%3A{sha}"
                   f"%20and%20lastVmScanDate%3A%5Bnow-{args.container_scan_days}d%20...%20now%5D")
            tmp_f = os.path.join(raw_dir, f"_cc_{sha[:12]}.json")

            if api.get(url, tmp_f):
                try:
                    d = json.load(open(tmp_f))
                    # Use "count" field if available, otherwise count data array
                    cc[sha] = d.get("count", len(d.get("data", [])))
                except Exception:
                    cc[sha] = 0
            else:
                cc[sha] = 0
            _rm(tmp_f)  # clean up temp file

            # Save progress every 50 SHAs (crash recovery)
            if fetched % 50 == 0:
                atomic_write_json(cc_file, cc)

        atomic_write_json(cc_file, cc)
        chk.mark("containers")  # checkpoint: Phase 3 done
        log.info(f"  Done: {total} SHAs, {fetched} fetched this run")

    # ==================================================================
    # PHASE 4: Generate CSV + JSON reports
    # ==================================================================
    log.info("\n[Phase 4] Generating reports...")
    enriched = enrich(images, eol_shas, cc, args.skip_containers)
    csv_rows = write_csv(enriched, os.path.join(od, "qualys_cs_unified_report.csv"), log)
    write_json(enriched, os.path.join(od, "images_full_report.json"), log)

    # ==================================================================
    # PHASE 5: Write run summary
    # ==================================================================
    duration = int(time.time() - t0)
    summary = {
        "version": VERSION,
        "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gateway": args.gateway,
        "filter": args.filter or f"(default: imagesInUse last {args.days}d)",
        "days": args.days,
        "container_scan_days": args.container_scan_days,
        "total_images": len(enriched),
        "unique_images": len(set(i["sha"] for i in enriched)),
        "eol_images": sum(1 for i in enriched if i["eol"]),
        "total_vulns": sum(i["vulnCount"] for i in enriched),
        "total_software": sum(len(i["sws"]) for i in enriched),
        "csv_rows": csv_rows,
        "duration": fmt_duration(duration),
        "api_calls": api.calls,
        "retries": api.retries_used,
        "errors": api.errors,
        "throttle_waits": rl.waits,
        "throttle_seconds": rl.wait_secs,
    }
    atomic_write_json(os.path.join(od, "run_summary.json"), summary)
    chk.mark("complete")  # checkpoint: all phases done

    # ── Final output ──
    log.info(f"\n{'='*50}")
    log.info(f"  DONE in {fmt_duration(duration)}")
    log.info(f"  Images: {summary['total_images']} | EOL: {summary['eol_images']} | Vulns: {summary['total_vulns']}")
    log.info(f"  CSV: {csv_rows:,} rows | API: {api.calls} calls, {api.retries_used} retries, {rl.waits} throttles")
    log.info(f"  Output: {od}/")
    log.info(f"{'='*50}")


if __name__ == "__main__":
    main()
