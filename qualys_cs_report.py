#!/usr/bin/env python3
"""
Qualys Container Security — Image Report Generator
====================================================
Version: 2.0.0

This script pulls container image data from Qualys CSAPI and produces
a single CSV + JSON report containing:
  - Image details (registry, repo, tag, OS, architecture)
  - Software inventory with lifecycle/EOL dates
  - Vulnerabilities with fix versions
  - Running container count per image
  - EOL Base OS flag (True/False/blank)

HOW IT WORKS (5 Phases):
  Phase 1: Fetch all images via Image Bulk API (paginated)
  Phase 2: Fetch EOL images via Image Bulk API with EOL filter
           Compare SHAs from Phase 1 vs Phase 2 to set EOL_Base_OS
  Phase 3: Fetch running container count per image SHA (PARALLEL)
  Phase 4: Combine all data into CSV + JSON
  Phase 5: Write run summary

IMPORTANT DESIGN DECISIONS:
  - HTTP 204 from Container API = 0 running containers (NOT an error)
  - OS is blank → EOL_Base_OS is also blank (can't determine EOL without OS)
  - created='0' in API means unknown → Image_Created is blank in CSV
  - Multi-repo images get separate rows per registry (no pipe-delimited)
  - Phase 3 uses parallel threads with a GLOBAL rate limiter
  - All threads share one rate-limit token bucket to avoid 429 storms

IDEMPOTENT: Re-run safely. Completed phases are skipped via checkpoint.
            Use --force for a fresh start.

PREREQUISITES: Python 3.8+, curl (no pip packages needed)
"""

# ============================================================================
# Imports (all standard library — no pip install needed)
# ============================================================================
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
from typing import Dict, List, Set

VERSION = "2.0.0"

# ============================================================================
# Default Configuration
# All values can be overridden via CLI flags or environment variables.
# ============================================================================
DEFAULT_GATEWAY             = "https://gateway.qg2.apps.qualys.com"
DEFAULT_API_VERSION         = "v1.3"
DEFAULT_PAGE_LIMIT          = 250    # max records per API page (Qualys max = 250)
DEFAULT_IMAGE_LOOKBACK_DAYS = 30     # fetch images used in the last N days
DEFAULT_CONTAINER_SCAN_DAYS = 3      # container scan lookback for running count
DEFAULT_MAX_RETRIES         = 2      # max retries per failed API call (fail fast)
DEFAULT_CONNECT_TIMEOUT     = 15     # curl connect timeout in seconds
DEFAULT_REQUEST_TIMEOUT     = 60     # curl max time per request in seconds
DEFAULT_THREAD_COUNT        = 5      # parallel threads for container count
DEFAULT_CALLS_PER_SECOND    = 2      # max API calls/sec across ALL threads


# ============================================================================
# Signal Handling — Ctrl+C saves state instead of crashing
# ============================================================================
_shutdown_requested = False

def _handle_signal(signal_number, _frame):
    """When user presses Ctrl+C or script receives SIGTERM,
    set a flag so the current operation finishes and state is saved."""
    global _shutdown_requested
    signal_name = signal.Signals(signal_number).name
    print(f"\n[!] {signal_name} received — saving state...", file=sys.stderr)
    _shutdown_requested = True

signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

def _exit_if_shutdown():
    """Check if shutdown was requested. Called inside all loops."""
    if _shutdown_requested:
        raise SystemExit(130)


# ============================================================================
# Helper Functions
# ============================================================================
def safe_string(value) -> str:
    """Convert None or the literal string 'None' to empty string.
    The Qualys API sometimes returns the STRING 'None' instead of null."""
    if value is None or value == "None":
        return ""
    return str(value)


def epoch_milliseconds_to_iso(epoch_ms) -> str:
    """Convert Qualys epoch-milliseconds timestamp to ISO 8601.
    Example: 1774303950426 → '2026-03-23T22:12:30Z'
    Returns empty string for null, zero, or invalid values."""
    if not epoch_ms or str(epoch_ms) == "0":
        return ""
    try:
        timestamp = int(epoch_ms) / 1000.0
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return str(epoch_ms)


def write_json_atomically(file_path: str, data):
    """Write JSON to a temporary file first, then rename it into place.
    This prevents corrupt files if the script crashes mid-write."""
    directory = os.path.dirname(file_path)
    file_descriptor, temp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(file_descriptor, "w") as temp_file:
            json.dump(data, temp_file, indent=2, default=str)
        os.replace(temp_path, file_path)  # atomic on same filesystem
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def format_duration(seconds: int) -> str:
    """Format seconds into human-readable string: 45s, 3m12s, 1h5m."""
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60}m"


def remove_file(file_path):
    """Silently remove a file. No error if it doesn't exist."""
    try:
        os.remove(file_path)
    except OSError:
        pass


def generate_config_fingerprint(args) -> str:
    """Create a short hash of all settings that affect API data.
    If the user changes --days, --filter, etc., the checkpoint auto-resets
    so stale cached data isn't mixed with new parameters."""
    config_string = (
        f"{args.gateway}|{args.days}|{args.container_scan_days}"
        f"|{args.limit}|{args.skip_containers}|{args.filter or ''}"
    )
    return hashlib.sha256(config_string.encode()).hexdigest()[:16]


def build_image_api_filter(lookback_days: int, extra_filter: str = "") -> str:
    """Build the URL-encoded filter string for the Image List API.
    Base: imagesInUse:[now-30d ... now]
    If extra_filter is provided (e.g. 'operatingSystem:Ubuntu'),
    it's appended with AND."""
    base_filter = f"imagesInUse%3A%60%5Bnow-{lookback_days}d%20...%20now%5D%60"
    if extra_filter:
        encoded_extra = extra_filter.replace(" ", "%20")
        return f"{base_filter}%20and%20{encoded_extra}"
    return base_filter


# ============================================================================
# Logging — writes to both console and a log file
# ============================================================================
def setup_logging(output_directory, verbose, quiet):
    """Configure dual logging: file (always verbose) + console (user-controlled)."""
    logger = logging.getLogger("qualys")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # Log file — captures everything including DEBUG
    log_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_file_path = os.path.join(output_directory, log_filename)
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    logger.addHandler(file_handler)

    # Console — INFO by default, DEBUG if --verbose, nothing if --quiet
    if not quiet:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console_handler)

    return logger, log_file_path


# ============================================================================
# Lock File — prevents two instances from running simultaneously
# ============================================================================
def acquire_lock(output_directory, force):
    """Create a .lock file with our PID. If another instance is running
    (PID is alive), refuse to start unless --force is used."""
    lock_path = os.path.join(output_directory, ".lock")

    if os.path.exists(lock_path):
        try:
            existing_pid = int(open(lock_path).read().strip())
            os.kill(existing_pid, 0)  # check if process is alive (signal 0 = no-op)
        except (ValueError, ProcessLookupError, PermissionError):
            pass  # PID is dead — stale lock, safe to override
        else:
            if not force:
                print(f"ERROR: Another instance running (PID {existing_pid}). Use --force.", file=sys.stderr)
                sys.exit(1)

    # Write our PID to the lock file
    open(lock_path, "w").write(str(os.getpid()))
    # Auto-remove lock when script exits (normal or error)
    atexit.register(lambda: remove_file(lock_path))


# ============================================================================
# Checkpoint — enables idempotent resume after crash or Ctrl+C
# ============================================================================
class Checkpoint:
    """Tracks which phases are done. Saved to .checkpoint.json.
    On re-run: completed phases are skipped (idempotent).
    If config changes (different fingerprint), checkpoint auto-resets."""

    def __init__(self, output_directory, fingerprint):
        self.file_path = os.path.join(output_directory, ".checkpoint.json")
        self.fingerprint = fingerprint
        self.state = {}

        if os.path.exists(self.file_path):
            try:
                self.state = json.load(open(self.file_path))
                # If config changed since last run, start fresh
                if self.state.get("fingerprint") != fingerprint:
                    self.state = {}
            except (json.JSONDecodeError, KeyError):
                self.state = {}

    def is_done(self, phase_name: str) -> bool:
        """Check if a phase was already completed."""
        return self.state.get(phase_name) is True

    def mark_done(self, phase_name: str):
        """Mark a phase as completed and save to disk."""
        self.state[phase_name] = True
        self.state["fingerprint"] = self.fingerprint
        write_json_atomically(self.file_path, self.state)

    def clear(self):
        """Delete checkpoint to force a fresh start."""
        remove_file(self.file_path)
        self.state = {}


# ============================================================================
# Global Rate Limiter — coordinates ALL threads to respect API limits
#
# The Qualys API returns these headers:
#   X-RateLimit-Remaining: calls left in the current time window
#   X-RateLimit-Window-Sec: window duration in seconds
#   Retry-After: seconds to wait (only on HTTP 429)
#
# This rate limiter uses a token bucket pattern:
#   - Every thread calls acquire() BEFORE making an API call
#   - acquire() blocks until a token is available (based on calls_per_second)
#   - When ANY thread gets remaining=0 or HTTP 429, ALL threads pause
#   - As remaining drops below 20, speed auto-reduces to 1 call/sec
# ============================================================================
class GlobalRateLimiter:
    def __init__(self, max_calls_per_second, logger):
        self.minimum_interval = 1.0 / max_calls_per_second  # seconds between calls
        self.logger = logger
        self._lock = threading.Lock()        # thread safety
        self._last_call_time = 0.0           # when the last call was made
        self._global_pause_until = 0.0       # all threads pause until this time
        self.api_limit = None                # from X-RateLimit-Limit header
        self.api_remaining = None            # from X-RateLimit-Remaining header
        self.api_window_seconds = None       # from X-RateLimit-Window-Sec header
        self.total_throttle_events = 0       # how many times we had to wait
        self.total_throttle_seconds = 0      # total time spent waiting

    def acquire(self):
        """Block until it's safe to make an API call.
        Every thread must call this BEFORE making a curl request."""
        while True:
            _exit_if_shutdown()
            with self._lock:
                now = time.time()

                # If globally paused (429 or rate limit exhausted), wait
                if now < self._global_pause_until:
                    wait_time = self._global_pause_until - now
                else:
                    # Enforce minimum interval between calls
                    elapsed_since_last = now - self._last_call_time
                    if elapsed_since_last < self.minimum_interval:
                        wait_time = self.minimum_interval - elapsed_since_last
                    else:
                        # Token available — proceed
                        self._last_call_time = time.time()
                        return

            # Sleep outside the lock (so other threads aren't blocked)
            time.sleep(wait_time)

    def update_from_response_headers(self, header_file_path):
        """Read rate-limit headers from a curl -D dump file and adapt speed."""
        if not os.path.exists(header_file_path):
            return

        remaining = None
        window_seconds = None

        try:
            for line in open(header_file_path):
                header_lower = line.lower().strip()
                if header_lower.startswith("x-ratelimit-remaining:"):
                    remaining = int(line.split(":", 1)[1].strip())
                elif header_lower.startswith("x-ratelimit-window-sec:"):
                    window_seconds = int(line.split(":", 1)[1].strip())
                elif header_lower.startswith("x-ratelimit-limit:"):
                    self.api_limit = int(line.split(":", 1)[1].strip())
        except (ValueError, IOError):
            return

        with self._lock:
            if remaining is not None:
                self.api_remaining = remaining
            if window_seconds is not None:
                self.api_window_seconds = window_seconds

            if remaining is not None:
                if remaining <= 0:
                    # Rate limit exhausted — pause ALL threads
                    pause_duration = (window_seconds or 60) + 5
                    self._global_pause_until = time.time() + pause_duration
                    self.logger.warning(f"  Rate limit exhausted (0 remaining) — all threads pausing {pause_duration}s")
                    self.total_throttle_events += 1
                    self.total_throttle_seconds += pause_duration
                elif remaining <= 20:
                    # Getting low — slow down to 1 call/sec
                    self.minimum_interval = max(self.minimum_interval, 1.0)
                    self.logger.debug(f"  Rate limit low ({remaining}) — slowed to 1/sec")

    def handle_http_429(self, header_file_path):
        """When HTTP 429 is received, pause ALL threads."""
        retry_after = None
        if os.path.exists(header_file_path):
            try:
                for line in open(header_file_path):
                    if line.lower().strip().startswith("retry-after:"):
                        retry_after = int(line.split(":", 1)[1].strip())
            except (ValueError, IOError):
                pass

        pause_duration = retry_after or (self.api_window_seconds or 30) + 5
        with self._lock:
            self._global_pause_until = time.time() + pause_duration
            self.logger.warning(f"  HTTP 429 received — all threads pausing {pause_duration}s")
            self.total_throttle_events += 1
            self.total_throttle_seconds += pause_duration


# ============================================================================
# API Client — handles all HTTP calls to Qualys CSAPI
#
# Thread-safe: can be shared across parallel threads.
# Key: HTTP 204 = valid "no content" response (0 containers), NOT an error.
# ============================================================================
class QualysAPIClient:
    def __init__(self, gateway, token, max_retries, connect_timeout,
                 request_timeout, curl_extra_args, rate_limiter, logger):
        self.gateway = gateway.rstrip("/")
        self.token = token
        self.max_retries = max_retries
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout
        self.curl_extra_args = curl_extra_args
        self.rate_limiter = rate_limiter
        self.logger = logger

        # Thread-safe counters
        self._counter_lock = threading.Lock()
        self._total_api_calls = 0
        self._total_retries = 0
        self._total_errors = 0

    @property
    def total_api_calls(self):
        with self._counter_lock:
            return self._total_api_calls

    @property
    def total_retries(self):
        with self._counter_lock:
            return self._total_retries

    @property
    def total_errors(self):
        with self._counter_lock:
            return self._total_errors

    def _increment_counters(self, calls=0, retries=0, errors=0):
        with self._counter_lock:
            self._total_api_calls += calls
            self._total_retries += retries
            self._total_errors += errors

    def make_request(self, url, output_file, keep_header_file=False):
        """Make a GET request with retry logic. Returns the HTTP status code.

        Return values:
          200 = success, response body in output_file
          204 = success, no content (e.g. 0 running containers)
          0   = all retries failed

        Retry policy:
          - 429 (rate limited): wait per Retry-After, then retry
          - 5xx (server error): short backoff, retry
          - Connection failure: short backoff, retry
          - 401/403/404: FATAL — exit immediately (no retry)
        """
        for attempt_number in range(self.max_retries + 1):
            _exit_if_shutdown()

            # Wait before retries (not on first attempt)
            if attempt_number > 0:
                backoff_seconds = random.uniform(1, min(15, 2 ** attempt_number))
                self.logger.debug(f"  Retry {attempt_number}/{self.max_retries} in {backoff_seconds:.0f}s")
                time.sleep(backoff_seconds)
                self._increment_counters(retries=1)

            # Wait for rate-limit token before making the call
            self.rate_limiter.acquire()

            # Execute curl
            header_file = output_file + ".hdr"
            curl_command = [
                "curl", "-s",
                "-o", output_file,            # save response body here
                "-D", header_file,            # save response headers here
                "-w", "%{http_code}",         # print HTTP code to stdout
                "--connect-timeout", str(self.connect_timeout),
                "--max-time", str(self.request_timeout),
                "-X", "GET", url,
                "-H", "Accept: application/json",
                "-H", f"Authorization: Bearer {self.token}",
            ]
            if self.curl_extra_args:
                curl_command.extend(self.curl_extra_args.split())

            try:
                result = subprocess.run(curl_command, capture_output=True, text=True)
                http_code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            except Exception as error:
                self.logger.debug(f"  curl error: {error}")
                self._increment_counters(calls=1, errors=1)
                continue

            self._increment_counters(calls=1)

            # Always read rate-limit headers (even on errors)
            self.rate_limiter.update_from_response_headers(header_file)

            # --- Handle response ---

            # SUCCESS: 200 = data returned, 204 = no content (valid)
            if http_code in (200, 204):
                if not keep_header_file:
                    remove_file(header_file)
                return http_code

            # FATAL errors — exit immediately, no retry
            if http_code == 401:
                self.logger.error("HTTP 401 — token expired or invalid")
                sys.exit(1)
            if http_code == 403:
                self.logger.error("HTTP 403 — insufficient permissions")
                sys.exit(1)
            if http_code == 404:
                self.logger.error(f"HTTP 404 — endpoint not found: {url}")
                sys.exit(1)

            # RETRYABLE errors
            if http_code == 429:
                self.rate_limiter.handle_http_429(header_file)

            remove_file(header_file)
            self._increment_counters(errors=1)

        # All retries exhausted
        return 0

    def fetch_all_pages(self, initial_url, pages_directory, label, page_size):
        """Fetch ALL pages from a paginated Qualys API endpoint.

        Qualys uses the Link header for pagination:
          Link: <next_page_url>;rel=next

        Resume logic:
          - Cached page + .hdr with Link → skip to next page
          - Cached partial page (< page_size) → last page, done
          - Cached full page but .hdr missing → re-fetch to recover Link
        """
        all_records = []
        page_number = 1
        current_url = initial_url

        while current_url:
            _exit_if_shutdown()

            page_file = os.path.join(pages_directory, f"{label}_{page_number:04d}.json")
            header_file = page_file + ".hdr"

            # --- Try to reuse cached page ---
            if os.path.exists(page_file):
                try:
                    page_data = json.load(open(page_file)).get("data", [])
                except (json.JSONDecodeError, KeyError, TypeError):
                    page_data = None  # corrupted — re-fetch below

                if isinstance(page_data, list) and len(page_data) > 0:
                    next_page_url = self._extract_next_url(header_file)

                    if next_page_url:
                        # Cached page with Link header → use it
                        all_records.extend(page_data)
                        self.logger.info(f"  {label} p{page_number}: {len(page_data)} (cached)")
                        current_url = next_page_url
                        page_number += 1
                        continue
                    elif len(page_data) < page_size:
                        # Partial page = last page
                        all_records.extend(page_data)
                        self.logger.info(f"  {label} p{page_number}: {len(page_data)} (cached, last)")
                        break
                    else:
                        # Full page but .hdr lost — must re-fetch
                        self.logger.info(f"  {label} p{page_number}: cached but Link lost — re-fetching")

            # --- Fresh fetch ---
            self.logger.info(f"  Fetching {label} page {page_number}...")
            http_code = self.make_request(current_url, page_file, keep_header_file=True)

            if http_code != 200:
                self.logger.error(f"  Failed on {label} page {page_number} (HTTP {http_code})")
                break

            # Parse response
            try:
                page_data = json.load(open(page_file)).get("data", [])
            except (json.JSONDecodeError, KeyError, TypeError):
                self.logger.warning(f"  Bad JSON on {label} page {page_number}")
                break
            if not isinstance(page_data, list):
                self.logger.warning(f"  Invalid data on {label} page {page_number}")
                break

            all_records.extend(page_data)
            self.logger.info(f"  {label} p{page_number}: {len(page_data)} (total: {len(all_records)})")

            # --- Determine next page ---
            next_page_url = self._extract_next_url(header_file)
            if next_page_url:
                # Clean up PREVIOUS page's .hdr (current one stays for resume)
                if page_number > 1:
                    previous_header = os.path.join(pages_directory, f"{label}_{page_number-1:04d}.json.hdr")
                    remove_file(previous_header)
                current_url = next_page_url
                page_number += 1
            else:
                # No Link header = last page
                remove_file(header_file)
                break

        # Clean up final .hdr
        remove_file(os.path.join(pages_directory, f"{label}_{page_number:04d}.json.hdr"))
        self.logger.info(f"  {label}: {len(all_records)} records total, {page_number} pages")
        return all_records

    @staticmethod
    def _extract_next_url(header_file_path):
        """Extract next page URL from the Link response header."""
        if not os.path.exists(header_file_path):
            return ""
        try:
            for line in open(header_file_path):
                if line.lower().startswith("link:"):
                    match = re.search(r'<([^>]+)>;rel=next', line)
                    if match:
                        return match.group(1)
        except Exception:
            pass
        return ""


# ============================================================================
# Phase 3: Parallel Container Count Fetcher
# ============================================================================
def fetch_container_counts_parallel(
    api_client, base_api_url, image_shas, container_scan_days,
    existing_counts, raw_directory, thread_count, logger
):
    """Fetch running container count for each image SHA using parallel threads.

    Key behaviors:
      - HTTP 200 = containers found, parse count from response JSON
      - HTTP 204 = zero running containers (valid, NOT an error)
      - Any other code = count as 0, move on (don't block the whole run)
      - All threads share the global rate limiter
      - Checkpoints to disk every 100 SHAs for crash recovery
    """
    # Filter out already-fetched SHAs (resume support)
    shas_to_fetch = [sha for sha in image_shas if sha not in existing_counts]
    if not shas_to_fetch:
        logger.info(f"  All {len(image_shas)} SHAs already cached")
        return existing_counts

    total_to_fetch = len(shas_to_fetch)
    logger.info(f"  {total_to_fetch} to fetch, {len(existing_counts)} cached — {thread_count} threads")

    counts_file_path = os.path.join(raw_directory, "container_counts.json")
    completed_count = 0
    progress_lock = threading.Lock()
    start_time = time.time()

    def _fetch_single_sha(image_sha):
        """Fetch container count for one SHA. Called by each thread."""
        nonlocal completed_count

        container_api_url = (
            f"{base_api_url}/containers"
            f"?filter=state%3A%20%60RUNNING%60%20and%20imageSha%3A{image_sha}"
            f"%20and%20lastVmScanDate%3A%5Bnow-{container_scan_days}d%20...%20now%5D"
        )

        # Use thread ID in temp filename to avoid collisions between threads
        thread_id = threading.current_thread().ident
        temp_file = os.path.join(raw_directory, f"_tmp_{image_sha[:12]}_{thread_id}.json")

        http_code = api_client.make_request(container_api_url, temp_file)

        container_count = 0
        if http_code == 200:
            # 200 = containers found — parse the count
            try:
                response_data = json.load(open(temp_file))
                container_count = response_data.get("count", len(response_data.get("data", [])))
            except Exception:
                pass
        # 204 = no running containers (count stays 0)
        # 0 or other = API call failed (count stays 0, move on)

        remove_file(temp_file)

        # Update shared state (thread-safe)
        with progress_lock:
            existing_counts[image_sha] = container_count
            completed_count += 1

            # Log progress every 50 SHAs
            if completed_count % 50 == 0 or completed_count == 1 or completed_count == total_to_fetch:
                elapsed = time.time() - start_time
                rate = elapsed / completed_count if completed_count > 0 else 1
                estimated_remaining = format_duration(int((total_to_fetch - completed_count) * rate))
                logger.info(f"  Containers: {completed_count}/{total_to_fetch} ({estimated_remaining} remaining)")

            # Checkpoint every 100 SHAs
            if completed_count % 100 == 0:
                write_json_atomically(counts_file_path, existing_counts)

    # Run threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(_fetch_single_sha, sha): sha for sha in shas_to_fetch}
        for future in concurrent.futures.as_completed(futures):
            _exit_if_shutdown()
            try:
                future.result()
            except Exception as error:
                logger.debug(f"  Thread error: {error}")

    # Final save
    write_json_atomically(counts_file_path, existing_counts)
    elapsed_total = int(time.time() - start_time)
    logger.info(f"  Done: {total_to_fetch} fetched in {format_duration(elapsed_total)}")
    return existing_counts


# ============================================================================
# Data Processing — transform raw API data into report-ready format
# ============================================================================
def extract_image_repositories(raw_image):
    """Extract all (registry, repository, tag) from an image record.
    Falls back to repoDigests for registry when repo.registry is null.
    Returns at least one entry so the image always gets a CSV row."""
    repo_list = raw_image.get("repo") or []
    digest_list = raw_image.get("repoDigests") or []

    # Build fallback: repository_name → registry from repoDigests
    registry_fallback = {
        digest["repository"]: digest["registry"]
        for digest in digest_list
        if digest.get("registry") and digest.get("repository")
    }

    result = []
    for repo_entry in repo_list:
        registry = repo_entry.get("registry")
        repository = safe_string(repo_entry.get("repository"))
        tag = safe_string(repo_entry.get("tag"))

        # If registry is null, try to find it from repoDigests
        if not registry and repository:
            registry = registry_fallback.get(repository, "")

        result.append({
            "registry": safe_string(registry),
            "repository": repository,
            "tag": tag,
        })

    # If no repos at all, return one empty entry
    return result or [{"registry": "", "repository": "", "tag": ""}]


def build_enriched_image_list(raw_images, eol_image_shas, container_counts, skip_containers):
    """Transform raw Qualys API records into enriched report records.

    Key logic for EOL_Base_OS:
      - If the image has an Operating System AND its SHA was returned by
        the EOL API call → True
      - If the image has an Operating System but SHA was NOT in EOL response → False
      - If the image has NO Operating System → blank (we can't determine EOL)
    """
    enriched_list = []

    for raw_image in raw_images:
        image_sha = raw_image.get("sha", "")
        operating_system = safe_string(raw_image.get("operatingSystem"))
        vulnerabilities = raw_image.get("vulnerabilities") or []
        software_list = raw_image.get("softwares") or []

        # EOL logic: blank OS → blank EOL (can't determine)
        if operating_system:
            is_eol_base_os = image_sha in eol_image_shas
        else:
            is_eol_base_os = ""  # blank — unknown OS means unknown EOL

        # Container count
        if skip_containers:
            running_containers = "N/A"
        else:
            running_containers = container_counts.get(image_sha, 0)

        enriched_list.append({
            "image_id":           safe_string(raw_image.get("imageId")),
            "image_sha":          image_sha,
            "operating_system":   operating_system,
            "eol_base_os":        is_eol_base_os,
            "architecture":       safe_string(raw_image.get("architecture")),
            "image_created":      epoch_milliseconds_to_iso(raw_image.get("created")),
            "image_last_scanned": epoch_milliseconds_to_iso(raw_image.get("lastScanned")),
            "image_scan_types":   raw_image.get("scanTypes") or [],
            "repositories":       extract_image_repositories(raw_image),
            "risk_score":         raw_image.get("riskScore"),
            "max_qds_score":      raw_image.get("maxQdsScore"),
            "qds_severity":       safe_string(raw_image.get("qdsSeverity")),
            "vulnerability_count": len(vulnerabilities),
            "running_containers": running_containers,
            "vulnerabilities":    vulnerabilities,
            "software_list":      software_list,
        })

    return enriched_list


# ============================================================================
# CSV Report — 28 columns, fully denormalized
# ============================================================================
CSV_HEADERS = [
    # Image columns (16)
    "Image_ID", "Image_SHA", "Operating_System", "EOL_Base_OS", "Architecture",
    "Image_Created", "Image_Last_Scanned", "Image_Scan_Types",
    "Registry", "Repository", "Image_Tag",
    "Risk_Score", "Max_QDS_Score", "QDS_Severity",
    "Total_Vulnerabilities_On_Image", "Running_Container_Count",
    # Software columns (5)
    "Software_Name", "Software_Installed_Version", "Software_Fix_Version",
    "Software_Lifecycle_Stage", "Software_EOL_Date",
    # Vulnerability columns (7)
    "Vuln_QID", "Vuln_Scan_Type", "Vuln_Type_Detected", "Vuln_First_Found",
    "Vuln_Affected_Software_Name", "Vuln_Affected_Software_Version", "Vuln_Fix_Version",
]

IMAGE_COLUMN_COUNT = 16
SOFTWARE_COLUMN_COUNT = 5
VULN_COLUMN_COUNT = 7
EMPTY_SOFTWARE_COLUMNS = [""] * SOFTWARE_COLUMN_COUNT
EMPTY_VULN_COLUMNS = [""] * VULN_COLUMN_COUNT


def _build_image_columns(image, repo_entry):
    """Build the 16 image-level columns for one CSV row."""
    return [
        image["image_id"],
        image["image_sha"],
        image["operating_system"],
        image["eol_base_os"],
        image["architecture"],
        image["image_created"],
        image["image_last_scanned"],
        " | ".join(safe_string(scan_type) for scan_type in image["image_scan_types"]),
        repo_entry["registry"],
        repo_entry["repository"],
        repo_entry["tag"],
        safe_string(image["risk_score"]),
        safe_string(image["max_qds_score"]),
        image["qds_severity"],
        image["vulnerability_count"],
        image["running_containers"],
    ]


def _build_software_columns(software_entry):
    """Build the 5 software-level columns for one CSV row."""
    lifecycle = software_entry.get("lifecycle") or {}
    return [
        safe_string(software_entry.get("name")),
        safe_string(software_entry.get("version")),
        safe_string(software_entry.get("fixVersion")),
        safe_string(lifecycle.get("stage")),
        epoch_milliseconds_to_iso(lifecycle.get("eolDate")),
    ]


def _build_vulnerability_columns(vulnerability, affected_software):
    """Build the 7 vulnerability-level columns for one CSV row."""
    return [
        safe_string(vulnerability.get("qid")),
        " | ".join(safe_string(st) for st in (vulnerability.get("scanType") or [])),
        safe_string(vulnerability.get("typeDetected")),
        epoch_milliseconds_to_iso(vulnerability.get("firstFound")),
        safe_string(affected_software.get("name")),
        safe_string(affected_software.get("version")),
        safe_string(affected_software.get("fixVersion")),
    ]


def generate_csv_report(enriched_images, output_path, logger):
    """Write the unified CSV report. Atomic write (temp → rename)."""
    temp_path = output_path + ".tmp"
    row_count = 0

    with open(temp_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(CSV_HEADERS)

        for image in enriched_images:
            # Build software lookup ONCE per image (not per repo)
            software_lookup = {
                (safe_string(sw.get("name")), safe_string(sw.get("version"))): sw
                for sw in image["software_list"]
            }

            # Each repo gets its own set of rows (no pipe-delimited values)
            for repo_entry in image["repositories"]:
                image_columns = _build_image_columns(image, repo_entry)
                assert len(image_columns) == IMAGE_COLUMN_COUNT

                software_already_written = set()

                # Pass 1: Vulnerability rows (primary)
                for vulnerability in image["vulnerabilities"]:
                    affected_software_list = vulnerability.get("software") or [{}]
                    for affected_sw in affected_software_list:
                        sw_key = (safe_string(affected_sw.get("name")),
                                  safe_string(affected_sw.get("version")))

                        # Try to match vuln's software → installed software
                        matched_software = software_lookup.get(sw_key)
                        software_columns = _build_software_columns(matched_software) if matched_software else EMPTY_SOFTWARE_COLUMNS
                        vuln_columns = _build_vulnerability_columns(vulnerability, affected_sw)

                        row = image_columns + software_columns + vuln_columns
                        assert len(row) == len(CSV_HEADERS)
                        writer.writerow(row)
                        row_count += 1

                        if matched_software:
                            software_already_written.add(sw_key)

                # Pass 2: Software-only rows (not covered by vulnerabilities)
                for software in image["software_list"]:
                    sw_key = (safe_string(software.get("name")),
                              safe_string(software.get("version")))
                    if sw_key not in software_already_written:
                        row = image_columns + _build_software_columns(software) + EMPTY_VULN_COLUMNS
                        assert len(row) == len(CSV_HEADERS)
                        writer.writerow(row)
                        row_count += 1

                # Pass 3: Bare image (no software, no vulnerabilities)
                if not image["software_list"] and not image["vulnerabilities"]:
                    row = image_columns + EMPTY_SOFTWARE_COLUMNS + EMPTY_VULN_COLUMNS
                    assert len(row) == len(CSV_HEADERS)
                    writer.writerow(row)
                    row_count += 1

    os.replace(temp_path, output_path)
    logger.info(f"  CSV: {output_path} ({row_count:,} rows)")
    return row_count


def generate_json_report(enriched_images, output_path, logger):
    """Write the full JSON report."""
    write_json_atomically(output_path, {
        "generatedAt": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "totalImages": len(enriched_images),
        "eolImages": sum(1 for img in enriched_images if img["eol_base_os"] is True),
        "images": enriched_images,
    })
    logger.info(f"  JSON: {output_path}")


# ============================================================================
# CLI Argument Parsing
# ============================================================================
def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="qualys_cs_report",
        description=f"Qualys Container Security — Image Report Generator v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  export QUALYS_ACCESS_TOKEN="eyJ..."
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com -f "operatingSystem:Ubuntu"
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --skip-containers
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --threads 10 --cps 3
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --dry-run
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --force
""",
    )
    env = os.environ.get

    parser.add_argument("-g", "--gateway", default=env("QUALYS_GATEWAY", DEFAULT_GATEWAY), help="Qualys gateway URL")
    parser.add_argument("-t", "--token", default=env("QUALYS_ACCESS_TOKEN", ""), help="Access token")
    parser.add_argument("-l", "--limit", type=int, default=int(env("QUALYS_LIMIT", DEFAULT_PAGE_LIMIT)), help="Records per page (1-250)")
    parser.add_argument("-d", "--days", type=int, default=int(env("QUALYS_DAYS", DEFAULT_IMAGE_LOOKBACK_DAYS)), help="Image lookback days")
    parser.add_argument("-D", "--container-scan-days", type=int, default=int(env("QUALYS_CONTAINER_SCAN_DAYS", DEFAULT_CONTAINER_SCAN_DAYS)), help="Container scan lookback days")
    parser.add_argument("-f", "--filter", default=env("QUALYS_FILTER", ""), help="Extra filter (e.g. 'operatingSystem:Ubuntu')")
    parser.add_argument("-o", "--output-dir", default=env("QUALYS_OUTPUT_DIR", "./qualys_report_output"), help="Output directory")
    parser.add_argument("--skip-containers", action="store_true", default=env("QUALYS_SKIP_CONTAINER_COUNT", "").lower() == "true", help="Skip container count (faster)")
    parser.add_argument("--force", action="store_true", help="Ignore checkpoint, fresh start")
    parser.add_argument("--threads", type=int, default=int(env("QUALYS_THREADS", DEFAULT_THREAD_COUNT)), help=f"Parallel threads (default: {DEFAULT_THREAD_COUNT})")
    parser.add_argument("--cps", type=int, default=int(env("QUALYS_CPS", DEFAULT_CALLS_PER_SECOND)), help=f"Max API calls/sec (default: {DEFAULT_CALLS_PER_SECOND})")
    parser.add_argument("-r", "--retries", type=int, default=DEFAULT_MAX_RETRIES, help=f"Max retries (default: {DEFAULT_MAX_RETRIES})")
    parser.add_argument("-C", "--curl-extra", default=env("QUALYS_CURL_EXTRA", ""), help="Extra curl args")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Show config, no API calls")

    return parser.parse_args()


# ============================================================================
# Main — orchestrates all 5 phases
# ============================================================================
def main():
    args = parse_arguments()
    start_time = time.time()

    # --- Validate inputs ---
    if not args.token:
        print("ERROR: Set QUALYS_ACCESS_TOKEN or use -t <token>", file=sys.stderr)
        sys.exit(1)
    if not args.gateway.startswith("https://"):
        print("ERROR: Gateway must use HTTPS", file=sys.stderr)
        sys.exit(1)

    # --- Setup directories, logging, lock ---
    output_dir = args.output_dir
    pages_dir = os.path.join(output_dir, "pages")
    raw_dir = os.path.join(output_dir, "raw")
    os.makedirs(pages_dir, exist_ok=True)
    os.makedirs(raw_dir, exist_ok=True)

    logger, log_file_path = setup_logging(output_dir, args.verbose, args.quiet)
    acquire_lock(output_dir, args.force)

    # --- Build API URLs ---
    base_api_url = f"{args.gateway.rstrip('/')}/csapi/{DEFAULT_API_VERSION}"
    image_filter = build_image_api_filter(args.days, args.filter)
    eol_filter = build_image_api_filter(
        args.days,
        f"vulnerabilities.title%3AEOL" + (f"%20and%20{args.filter.replace(' ', '%20')}" if args.filter else "")
    )
    image_list_url = f"{base_api_url}/images/list?filter={image_filter}&limit={args.limit}"
    eol_list_url = f"{base_api_url}/images/list?filter={eol_filter}&limit={args.limit}"

    # --- Banner ---
    logger.info(f"Qualys CS Report Generator v{VERSION}")
    logger.info(f"Gateway:     {args.gateway}")
    logger.info(f"Output:      {output_dir}")
    logger.info(f"Params:      limit={args.limit} days={args.days} container_days={args.container_scan_days}")
    logger.info(f"Performance: {args.threads} threads, {args.cps} calls/sec max, {args.retries} retries")
    if args.filter:
        logger.info(f"Filter:      {args.filter}")

    # --- Dry run ---
    if args.dry_run:
        logger.info(f"\nDRY RUN — no API calls will be made")
        logger.info(f"Image API:     {image_list_url}")
        logger.info(f"EOL API:       {eol_list_url}")
        logger.info(f"Container API: {base_api_url}/containers?filter=state:RUNNING+imageSha:<SHA>+lastVmScanDate:[now-{args.container_scan_days}d...now]")
        return

    # --- Checkpoint (idempotent resume) ---
    checkpoint = Checkpoint(output_dir, generate_config_fingerprint(args))
    if checkpoint.is_done("complete") and not args.force:
        logger.info("Previous run already complete. Use --force for fresh start.")
        return
    if args.force:
        checkpoint.clear()

    # --- Create rate limiter and API client ---
    rate_limiter = GlobalRateLimiter(args.cps, logger)
    api_client = QualysAPIClient(
        args.gateway, args.token, args.retries,
        DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
        args.curl_extra, rate_limiter, logger,
    )

    # ================================================================
    # PHASE 1: Fetch all images
    # ================================================================
    all_images_file = os.path.join(raw_dir, "all_images.json")
    if checkpoint.is_done("images"):
        logger.info("\n[Phase 1] Images — cached")
        all_images = json.load(open(all_images_file))
    else:
        logger.info("\n[Phase 1] Fetching images...")
        all_images = api_client.fetch_all_pages(image_list_url, pages_dir, "img", args.limit)
        write_json_atomically(all_images_file, all_images)
        checkpoint.mark_done("images")
    logger.info(f"  Total: {len(all_images)} images")
    if not all_images:
        logger.warning("  WARNING: 0 images returned. Check gateway, token, and filter.")

    # ================================================================
    # PHASE 2: Fetch EOL images and compare SHAs
    # ================================================================
    eol_shas_file = os.path.join(raw_dir, "eol_shas.json")
    if checkpoint.is_done("eol"):
        logger.info("\n[Phase 2] EOL images — cached")
        eol_image_shas = set(json.load(open(eol_shas_file)))
    else:
        logger.info("\n[Phase 2] Fetching EOL images...")
        eol_images = api_client.fetch_all_pages(eol_list_url, pages_dir, "eol", args.limit)
        eol_image_shas = set(img["sha"] for img in eol_images if img.get("sha"))
        write_json_atomically(eol_shas_file, list(eol_image_shas))
        checkpoint.mark_done("eol")
    logger.info(f"  EOL images: {len(eol_image_shas)}")

    # ================================================================
    # PHASE 3: Fetch container counts (PARALLEL)
    # ================================================================
    container_counts = {}
    if args.skip_containers:
        logger.info("\n[Phase 3] Container counts — skipped")
    elif checkpoint.is_done("containers"):
        logger.info("\n[Phase 3] Container counts — cached")
        container_counts = json.load(open(os.path.join(raw_dir, "container_counts.json")))
    else:
        logger.info("\n[Phase 3] Fetching container counts (parallel)...")
        unique_shas = list(set(img["sha"] for img in all_images if img.get("sha")))

        # Load partial progress (resume after Ctrl+C)
        counts_file = os.path.join(raw_dir, "container_counts.json")
        if os.path.exists(counts_file):
            try:
                container_counts = json.load(open(counts_file))
            except (json.JSONDecodeError, KeyError):
                container_counts = {}

        container_counts = fetch_container_counts_parallel(
            api_client, base_api_url, unique_shas, args.container_scan_days,
            container_counts, raw_dir, args.threads, logger,
        )
        checkpoint.mark_done("containers")

    # ================================================================
    # PHASE 4: Generate reports
    # ================================================================
    logger.info("\n[Phase 4] Generating reports...")
    enriched_images = build_enriched_image_list(all_images, eol_image_shas, container_counts, args.skip_containers)
    csv_row_count = generate_csv_report(enriched_images, os.path.join(output_dir, "qualys_cs_unified_report.csv"), logger)
    generate_json_report(enriched_images, os.path.join(output_dir, "images_full_report.json"), logger)

    # ================================================================
    # PHASE 5: Run summary
    # ================================================================
    total_duration = int(time.time() - start_time)
    run_summary = {
        "version": VERSION,
        "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gateway": args.gateway,
        "filter": args.filter or f"imagesInUse last {args.days}d",
        "total_images": len(enriched_images),
        "unique_images": len(set(img["image_sha"] for img in enriched_images)),
        "eol_images": sum(1 for img in enriched_images if img["eol_base_os"] is True),
        "total_vulnerabilities": sum(img["vulnerability_count"] for img in enriched_images),
        "csv_rows": csv_row_count,
        "duration": format_duration(total_duration),
        "api_calls": api_client.total_api_calls,
        "retries": api_client.total_retries,
        "errors": api_client.total_errors,
        "throttle_events": rate_limiter.total_throttle_events,
        "throttle_seconds": rate_limiter.total_throttle_seconds,
        "threads": args.threads,
        "calls_per_second": args.cps,
    }
    write_json_atomically(os.path.join(output_dir, "run_summary.json"), run_summary)
    checkpoint.mark_done("complete")

    # --- Final output ---
    logger.info(f"\n{'=' * 55}")
    logger.info(f"  DONE in {format_duration(total_duration)}")
    logger.info(f"  Images: {run_summary['total_images']} | EOL: {run_summary['eol_images']} | Vulns: {run_summary['total_vulnerabilities']}")
    logger.info(f"  CSV: {csv_row_count:,} rows | API: {api_client.total_api_calls} calls | Throttles: {rate_limiter.total_throttle_events}")
    logger.info(f"  Output: {output_dir}/")
    logger.info(f"{'=' * 55}")


if __name__ == "__main__":
    main()
