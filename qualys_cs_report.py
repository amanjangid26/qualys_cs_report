#!/usr/bin/env python3
"""
=============================================================================
  Qualys Container Security — Image Report Generator
  Version: 2.2.0
=============================================================================

  WHAT THIS SCRIPT DOES:

  It talks to Qualys Container Security APIs and builds a single CSV + JSON
  report containing every container image, its installed software, known
  vulnerabilities, lifecycle dates, running container count, and whether
  the base operating system is end-of-life.

  HOW IT WORKS (5 phases):

  Phase 1 — IMAGE LIST
      Calls the Qualys Image Bulk API to fetch all container images that
      were in use during the last N days. Handles pagination automatically
      (the API returns 250 images per page, so if you have 5000 images,
      it fetches 20 pages).

  Phase 2 — EOL BASE OS DETECTION
      Calls the same Image API but with an extra filter:
      "vulnerabilities.title:EOL". This returns only images where Qualys
      has detected that the base operating system is end-of-life.
      We collect their SHA hashes and compare them against Phase 1:
          SHA found in both AND image has an OS → EOL_Base_OS = True
          SHA only in Phase 1 AND image has an OS → EOL_Base_OS = False
          Image has NO OS (distroless/scratch) → EOL_Base_OS = empty
              (evaluating EOL on a non-existent OS makes no sense)

  Phase 3 — CONTAINER COUNTS (parallel)
      For each unique image SHA from Phase 1, calls the Container API
      to find out how many running containers are using that image.
      This tells you the "blast radius" — if an image has a critical
      vulnerability and 50 running containers, that's urgent.
      Uses multiple threads (default: 5) for speed, with a global
      rate limiter so we don't exceed Qualys API limits.

  Phase 4 — REPORT GENERATION
      Combines all the data into a single flat CSV file (one row per
      vulnerability or software per image) and a JSON file.
      CSV has 32 columns including Software_Package_Path.

  Phase 5 — RUN SUMMARY
      Writes a summary JSON with stats: how many images, vulns, API calls,
      how long it took, etc.

  IDEMPOTENT (safe to re-run):
      Each phase saves a checkpoint. If the script crashes or you press
      Ctrl+C, just run it again — it picks up where it left off.
      Use --force to start completely fresh.

  PREREQUISITES:
      Python 3.8 or newer
      curl (command-line tool — pre-installed on most systems)
      No pip packages needed — uses only Python standard library.

=============================================================================
"""

# =============================================================================
# IMPORTS — all from Python standard library (no pip install needed)
# =============================================================================
import argparse          # command-line argument parsing
import atexit            # run cleanup code when script exits
import concurrent.futures  # parallel execution (thread pool)
import csv               # CSV file writing
import hashlib           # config fingerprint for checkpoint
import json              # JSON parsing and writing
import logging           # structured logging to console + file
import os                # file/directory operations
import random            # jitter for retry backoff
import re                # regex for parsing Link headers
import signal            # catch Ctrl+C gracefully
import subprocess        # run curl commands
import sys               # exit codes, stderr
import tempfile          # atomic file writes
import threading         # thread-safe locks for parallel execution
import time              # timing, sleep
from datetime import datetime, timezone  # timestamps


# =============================================================================
# VERSION
# =============================================================================
VERSION = "2.2.0"


# =============================================================================
# DEFAULT CONFIGURATION
# All of these can be overridden via command-line flags or environment variables.
# =============================================================================
DEFAULT_GATEWAY             = "https://gateway.qg2.apps.qualys.com"
DEFAULT_API_VERSION         = "v1.3"
DEFAULT_PAGE_LIMIT          = 250   # max images per API page (Qualys max is 250)
DEFAULT_IMAGE_LOOKBACK_DAYS = 30    # fetch images used in the last N days
DEFAULT_CONTAINER_SCAN_DAYS = 3     # container scan lookback for running count
DEFAULT_MAX_RETRIES         = 2     # retry failed API calls up to 2 times (fail fast)
DEFAULT_CONNECT_TIMEOUT     = 15    # seconds to wait for connection
DEFAULT_REQUEST_TIMEOUT     = 60    # seconds max per request
DEFAULT_THREAD_COUNT        = 5     # parallel threads for container counts
DEFAULT_CALLS_PER_SECOND    = 2     # max API calls per second (across all threads)


# =============================================================================
# GRACEFUL SHUTDOWN — Ctrl+C saves state instead of crashing
# =============================================================================
shutdown_requested = False

def handle_shutdown_signal(signal_number, _frame):
    """Called when user presses Ctrl+C or system sends SIGTERM (e.g. kill).
    Sets a flag so the main loops can exit cleanly and save progress."""
    global shutdown_requested
    signal_name = signal.Signals(signal_number).name
    print(f"\n[!] {signal_name} received — saving progress and exiting...", file=sys.stderr)
    shutdown_requested = True

# Register the handler for both Ctrl+C (SIGINT) and kill (SIGTERM)
signal.signal(signal.SIGINT, handle_shutdown_signal)
signal.signal(signal.SIGTERM, handle_shutdown_signal)

def check_if_shutdown_requested():
    """Called inside loops. If Ctrl+C was pressed, exit with code 130.
    The checkpoint file is already saved, so next run will resume."""
    if shutdown_requested:
        raise SystemExit(130)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def convert_to_safe_string(value):
    """Convert any value to a string safe for CSV output.

    - Python None → empty string
    - The literal string "None" (which Qualys API sometimes returns
      instead of null) → empty string
    - Everything else → str(value)

    Examples:
        convert_to_safe_string(None)      → ""
        convert_to_safe_string("None")    → ""
        convert_to_safe_string(12345)     → "12345"
        convert_to_safe_string("openssl") → "openssl"
    """
    if value is None or value == "None":
        return ""
    return str(value)


def convert_epoch_ms_to_iso(epoch_milliseconds):
    """Convert a Qualys timestamp (epoch milliseconds) to ISO 8601 format.

    Qualys stores timestamps as milliseconds since Jan 1, 1970.
    Example: 1774303950426 → "2026-03-23T22:12:30Z"

    Special cases:
        - None or empty → ""
        - "0" → "" (not "1970-01-01" — epoch 0 means "no date recorded")

    Args:
        epoch_milliseconds: string or int like "1774303950426" or 0

    Returns:
        ISO 8601 string like "2026-03-23T22:12:30Z", or "" if no valid date
    """
    if not epoch_milliseconds or str(epoch_milliseconds) == "0":
        return ""
    try:
        seconds = int(epoch_milliseconds) / 1000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return str(epoch_milliseconds)


def write_json_atomically(file_path, data):
    """Write JSON data to a file without risk of corruption.

    Why "atomically"? If the script crashes mid-write, the file could be
    half-written and corrupt. Instead, we:
    1. Write to a temporary file (e.g. report.json.tmp)
    2. Rename the temp file to the final name (this is instant on the OS)

    If the script crashes during step 1, the temp file is garbage but the
    original file is untouched. If it crashes during step 2... well, rename
    is atomic on any filesystem, so it can't half-happen.
    """
    file_descriptor, temp_path = tempfile.mkstemp(
        dir=os.path.dirname(file_path), suffix=".tmp"
    )
    try:
        with os.fdopen(file_descriptor, "w") as temp_file:
            json.dump(data, temp_file, indent=2, default=str)
        os.replace(temp_path, file_path)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def format_duration(total_seconds):
    """Format seconds into human-readable duration.

    Examples:
        45    → "45s"
        125   → "2m5s"
        3700  → "1h1m"
    """
    if total_seconds < 60:
        return f"{total_seconds}s"
    if total_seconds < 3600:
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        return f"{minutes}m{seconds}s"
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    return f"{hours}h{minutes}m"


def remove_file_silently(file_path):
    """Delete a file without throwing an error if it doesn't exist."""
    try:
        os.remove(file_path)
    except OSError:
        pass


def generate_config_fingerprint(args):
    """Create a short hash of the configuration that affects API data.

    Used by the checkpoint system: if you change --days, --filter, etc.,
    the fingerprint changes, and the checkpoint auto-resets so you don't
    mix stale cached data with new parameters.
    """
    config_string = (
        f"{args.gateway}|{args.days}|{args.container_scan_days}"
        f"|{args.limit}|{args.skip_containers}|{args.filter or ''}"
    )
    return hashlib.sha256(config_string.encode()).hexdigest()[:16]


def build_image_api_filter(lookback_days, extra_filter=""):
    """Build the URL-encoded filter string for the Qualys Image List API.

    Base filter: "imagesInUse:[now-30d ... now]"
    (URL-encoded because the API requires it)

    If extra_filter is provided (e.g. "operatingSystem:Ubuntu"), it's
    appended with AND:
    "imagesInUse:[now-30d ... now] and operatingSystem:Ubuntu"
    """
    base = f"imagesInUse%3A%60%5Bnow-{lookback_days}d%20...%20now%5D%60"
    if extra_filter:
        encoded_extra = extra_filter.replace(" ", "%20")
        return f"{base}%20and%20{encoded_extra}"
    return base


# =============================================================================
# LOGGING — writes to both console (for humans) and a log file (for debugging)
# =============================================================================

def setup_logging(output_directory, verbose_mode, quiet_mode):
    """Create a logger that writes to both console and a timestamped log file.

    - Console: shows INFO messages (or DEBUG if --verbose, nothing if --quiet)
    - Log file: always captures everything (DEBUG level) for troubleshooting
    """
    logger = logging.getLogger("qualys")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()  # prevent duplicate handlers on re-run

    # Log file — always verbose, timestamps included
    log_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_file_path = os.path.join(output_directory, log_filename)
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    logger.addHandler(file_handler)

    # Console — controlled by --verbose and --quiet flags
    if not quiet_mode:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if verbose_mode else logging.INFO)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console_handler)

    return logger, log_file_path


# =============================================================================
# LOCK FILE — prevents two copies of the script from running simultaneously
# =============================================================================

def acquire_lock_file(output_directory, force_mode):
    """Create a .lock file with our process ID.

    If another instance is already running (its PID is still alive),
    we refuse to start — unless --force is used.

    The lock file is automatically deleted when the script exits
    (via atexit), even if it crashes.
    """
    lock_path = os.path.join(output_directory, ".lock")

    if os.path.exists(lock_path):
        try:
            existing_pid = int(open(lock_path).read().strip())
            os.kill(existing_pid, 0)  # check if process is alive (doesn't actually kill it)
            # If we get here, the process IS alive
            if not force_mode:
                print(f"ERROR: Another instance is running (PID {existing_pid}). Use --force to override.",
                      file=sys.stderr)
                sys.exit(1)
        except (ValueError, ProcessLookupError, PermissionError):
            pass  # stale lock from a dead process — safe to take over

    # Write our PID and register cleanup
    open(lock_path, "w").write(str(os.getpid()))
    atexit.register(lambda: remove_file_silently(lock_path))


# =============================================================================
# CHECKPOINT — enables the script to resume after crashes (idempotent)
# =============================================================================

class CheckpointManager:
    """Tracks which phases are complete. Saved to disk as JSON.

    How it works:
    - After Phase 1 completes, we call checkpoint.mark_complete("images")
    - If the script crashes during Phase 3, Phase 1 and 2 are still marked done
    - On re-run, Phases 1 and 2 are skipped (data loaded from cache)
    - Phase 3 resumes from where it left off

    If you change the config (e.g. --days 7 instead of --days 30), the
    fingerprint changes and the checkpoint auto-resets to avoid mixing
    stale data with new parameters.
    """

    def __init__(self, output_directory, config_fingerprint):
        self.file_path = os.path.join(output_directory, ".checkpoint.json")
        self.fingerprint = config_fingerprint
        self.state = {}

        # Load existing checkpoint if it exists
        if os.path.exists(self.file_path):
            try:
                self.state = json.load(open(self.file_path))
                # If config changed, discard the old checkpoint
                if self.state.get("fingerprint") != config_fingerprint:
                    self.state = {}
            except (json.JSONDecodeError, KeyError):
                self.state = {}

    def is_phase_complete(self, phase_name):
        """Check if a phase was already completed in a previous run."""
        return self.state.get(phase_name) is True

    def mark_complete(self, phase_name):
        """Mark a phase as done and save to disk immediately."""
        self.state[phase_name] = True
        self.state["fingerprint"] = self.fingerprint
        write_json_atomically(self.file_path, self.state)

    def clear_all(self):
        """Reset checkpoint — used with --force."""
        remove_file_silently(self.file_path)
        self.state = {}


# =============================================================================
# GLOBAL RATE LIMITER — coordinates ALL threads to respect Qualys API limits
#
# Qualys returns these headers on every API response:
#   X-RateLimit-Remaining: 287   (calls left in current window)
#   X-RateLimit-Window-Sec: 300  (window = 5 minutes)
#   Retry-After: 30              (only on HTTP 429 — "please wait this long")
#
# Our strategy:
#   1. Every thread calls acquire() BEFORE making an API call
#   2. acquire() blocks until it's safe to proceed
#   3. A "token bucket" ensures we don't exceed calls_per_second
#   4. If any thread gets 429 or sees remaining=0, ALL threads pause
# =============================================================================

class GlobalRateLimiter:
    """Thread-safe rate limiter that coordinates all parallel API calls."""

    def __init__(self, max_calls_per_second, logger):
        self.minimum_interval = 1.0 / max_calls_per_second  # e.g. 0.5s for 2 cps
        self.logger = logger
        self.lock = threading.Lock()
        self.last_call_time = 0.0
        self.global_pause_until = 0.0  # all threads wait until this timestamp
        self.last_known_remaining = None
        self.last_known_window = None
        self.total_throttle_events = 0
        self.total_throttle_seconds = 0

    def acquire(self):
        """Block until it's safe to make an API call.

        Every thread must call this before making a request.
        It enforces:
        - Global pause (after 429 or remaining=0)
        - Minimum interval between calls (token bucket)
        """
        while True:
            check_if_shutdown_requested()
            with self.lock:
                now = time.time()

                # If globally paused (429 recovery), wait
                if now < self.global_pause_until:
                    wait_seconds = self.global_pause_until - now
                    self.lock.release()
                    time.sleep(wait_seconds)
                    self.lock.acquire()
                    continue

                # Enforce minimum interval between calls
                time_since_last = now - self.last_call_time
                if time_since_last < self.minimum_interval:
                    wait_seconds = self.minimum_interval - time_since_last
                    self.lock.release()
                    time.sleep(wait_seconds)
                    self.lock.acquire()
                    continue

                # All clear — record this call and proceed
                self.last_call_time = time.time()
                return

    def read_rate_limit_headers(self, header_file_path):
        """Parse Qualys rate-limit headers and adjust throttling.

        Called after every API response. If remaining calls are low,
        we slow down. If exhausted, we pause all threads.
        """
        if not os.path.exists(header_file_path):
            return

        remaining = None
        window_seconds = None

        try:
            for line in open(header_file_path):
                lower_line = line.lower().strip()
                if lower_line.startswith("x-ratelimit-remaining:"):
                    remaining = int(line.split(":", 1)[1].strip())
                elif lower_line.startswith("x-ratelimit-window-sec:"):
                    window_seconds = int(line.split(":", 1)[1].strip())
        except (ValueError, IOError):
            return

        with self.lock:
            if remaining is not None:
                self.last_known_remaining = remaining
            if window_seconds is not None:
                self.last_known_window = window_seconds

            if remaining is not None and remaining <= 0:
                # Rate limit exhausted — pause ALL threads
                pause_duration = (window_seconds or 60) + 5
                self.global_pause_until = time.time() + pause_duration
                self.logger.warning(
                    f"  Rate limit exhausted (0 remaining) — "
                    f"ALL threads pausing {pause_duration}s"
                )
                self.total_throttle_events += 1
                self.total_throttle_seconds += pause_duration

            elif remaining is not None and remaining <= 20:
                # Getting low — slow down to 1 call per second
                self.minimum_interval = max(self.minimum_interval, 1.0)
                self.logger.debug(f"  Rate limit low ({remaining} left) — slowing down")

    def handle_http_429(self, header_file_path):
        """Handle HTTP 429 (Too Many Requests) — pause ALL threads.

        If the response includes a Retry-After header, wait that long.
        Otherwise, wait for the rate limit window to reset.
        """
        retry_after = None
        if os.path.exists(header_file_path):
            try:
                for line in open(header_file_path):
                    if line.lower().strip().startswith("retry-after:"):
                        retry_after = int(line.split(":", 1)[1].strip())
            except (ValueError, IOError):
                pass

        pause_duration = retry_after or (self.last_known_window or 30) + 5

        with self.lock:
            self.global_pause_until = time.time() + pause_duration
            self.logger.warning(f"  HTTP 429 — ALL threads pausing {pause_duration}s")
            self.total_throttle_events += 1
            self.total_throttle_seconds += pause_duration


# =============================================================================
# API CLIENT — makes HTTP requests to Qualys with retry and rate-limiting
# =============================================================================

class QualysApiClient:
    """Handles all communication with the Qualys CSAPI.

    Features:
    - Retries failed requests with exponential backoff + jitter
    - Treats HTTP 204 as success (zero containers — not an error!)
    - Coordinates with GlobalRateLimiter for thread-safe rate limiting
    - Thread-safe counters for metrics
    """

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

        # Thread-safe counters
        self._counter_lock = threading.Lock()
        self._total_api_calls = 0
        self._total_retries = 0
        self._total_errors = 0

    # --- Thread-safe metric accessors ---
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

    def _calculate_retry_delay(self, attempt_number):
        """Exponential backoff with jitter: random(1, min(15, 2^attempt)).

        Why jitter? If 5 threads all fail at the same time and retry
        after exactly 4 seconds, they'll all collide again. Random jitter
        spreads them out.
        """
        max_delay = min(15, 2 ** attempt_number)
        return random.uniform(1, max_delay)

    def make_request(self, url, output_file_path, keep_headers=False):
        """Make a GET request to the Qualys API.

        Args:
            url: Full API URL
            output_file_path: Where to save the response body
            keep_headers: If True, keep the .hdr file (needed for pagination)

        Returns:
            HTTP status code: 200 (success), 204 (no content), or 0 (all retries failed)

        HTTP status handling:
            200 → Success, response body saved to output_file_path
            204 → Success, no content (e.g. zero running containers)
            401 → Token expired — script exits immediately
            403 → No permission — script exits immediately
            404 → URL not found — script exits immediately
            429 → Rate limited — wait and retry
            5xx → Server error — retry with backoff
            0   → Connection failed — retry with backoff
        """
        for attempt in range(self.max_retries + 1):
            check_if_shutdown_requested()

            # Wait before retry (not on first attempt)
            if attempt > 0:
                delay = self._calculate_retry_delay(attempt)
                self.logger.debug(f"  Retry {attempt}/{self.max_retries} in {delay:.0f}s")
                time.sleep(delay)
                self._increment_counters(retries=1)

            # Wait for rate limiter approval before making the call
            self.rate_limiter.acquire()

            # Build the curl command
            header_file = output_file_path + ".hdr"
            curl_command = [
                "curl", "-s",                             # silent mode
                "-o", output_file_path,                   # save response body here
                "-D", header_file,                        # save response headers here
                "-w", "%{http_code}",                     # print HTTP status to stdout
                "--connect-timeout", str(self.connect_timeout),
                "--max-time", str(self.request_timeout),
                "-X", "GET", url,
                "-H", "Accept: application/json",
                "-H", f"Authorization: Bearer {self.token}",
            ]
            if self.extra_curl_args:
                curl_command.extend(self.extra_curl_args.split())

            # Execute curl
            try:
                result = subprocess.run(curl_command, capture_output=True, text=True)
                http_code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            except Exception as error:
                self.logger.debug(f"  curl error: {error}")
                self._increment_counters(calls=1, errors=1)
                continue

            self._increment_counters(calls=1)
            self.rate_limiter.read_rate_limit_headers(header_file)

            # Handle the response
            if http_code in (200, 204):
                # Success! Clean up headers unless caller needs them
                if not keep_headers:
                    remove_file_silently(header_file)
                return http_code

            if http_code == 401:
                self.logger.error("HTTP 401 — Access token expired or invalid.")
                self.logger.error("Generate a new token: Qualys CS → Configurations → Access Token")
                sys.exit(1)

            if http_code == 403:
                self.logger.error("HTTP 403 — Insufficient permissions. Check token scope.")
                sys.exit(1)

            if http_code == 404:
                self.logger.error(f"HTTP 404 — Endpoint not found: {url}")
                self.logger.error("Check your gateway URL and API version.")
                sys.exit(1)

            if http_code == 429:
                self.rate_limiter.handle_http_429(header_file)
            else:
                self.logger.debug(f"  HTTP {http_code}")

            remove_file_silently(header_file)
            self._increment_counters(errors=1)

        # All retries exhausted
        return 0

    def fetch_all_pages(self, initial_url, pages_directory, label, page_size):
        """Fetch all pages from a paginated Qualys API endpoint.

        Qualys uses the HTTP Link header for pagination:
            Link: <https://...?page=2>;rel=next

        When there's no Link header, we've reached the last page.

        For crash-safe resume:
        - Each page is saved to disk
        - The .hdr file (containing the Link to next page) is kept until
          the NEXT page is saved
        - If .hdr is lost (crash between pages), the page is re-fetched

        Args:
            initial_url: First page URL
            pages_directory: Where to save per-page JSON files
            label: Label for log messages (e.g. "img", "eol")
            page_size: The --limit value (used to detect last page)

        Returns:
            List of all records across all pages
        """
        all_records = []
        current_page = 1
        current_url = initial_url

        while current_url:
            check_if_shutdown_requested()

            page_file = os.path.join(pages_directory, f"{label}_{current_page:04d}.json")
            header_file = page_file + ".hdr"

            # ── Try to reuse a previously cached page ──
            if os.path.exists(page_file):
                try:
                    page_data = json.load(open(page_file)).get("data", [])
                except (json.JSONDecodeError, KeyError, TypeError):
                    page_data = None  # corrupted — re-fetch

                if isinstance(page_data, list) and len(page_data) > 0:
                    next_page_url = self._extract_next_page_url(header_file)

                    if next_page_url:
                        # Have cached page + Link header → use it
                        all_records.extend(page_data)
                        self.logger.info(f"  {label} page {current_page}: {len(page_data)} records (cached)")
                        current_url = next_page_url
                        current_page += 1
                        continue

                    elif len(page_data) < page_size:
                        # Cached partial page = last page
                        all_records.extend(page_data)
                        self.logger.info(f"  {label} page {current_page}: {len(page_data)} records (cached, last page)")
                        break

                    else:
                        # Full page but .hdr is missing → re-fetch to recover Link
                        self.logger.info(f"  {label} page {current_page}: cached but Link header lost — re-fetching")

            # ── Fresh fetch from API ──
            self.logger.info(f"  Fetching {label} page {current_page}...")
            http_code = self.make_request(current_url, page_file, keep_headers=True)

            if http_code != 200:
                self.logger.error(f"  Failed on {label} page {current_page} (HTTP {http_code})")
                break

            # Parse response
            try:
                page_data = json.load(open(page_file)).get("data", [])
            except (json.JSONDecodeError, KeyError, TypeError):
                self.logger.warning(f"  Bad JSON on {label} page {current_page}")
                break

            if not isinstance(page_data, list):
                self.logger.warning(f"  Invalid response on {label} page {current_page}")
                break

            all_records.extend(page_data)
            self.logger.info(
                f"  {label} page {current_page}: {len(page_data)} records "
                f"(total: {len(all_records)})"
            )

            # ── Check for next page ──
            next_page_url = self._extract_next_page_url(header_file)

            if next_page_url:
                # Clean up PREVIOUS page's header (current page's stays for resume)
                if current_page > 1:
                    prev_header = os.path.join(
                        pages_directory, f"{label}_{current_page - 1:04d}.json.hdr"
                    )
                    remove_file_silently(prev_header)
                current_url = next_page_url
                current_page += 1
            else:
                # No Link header = last page
                remove_file_silently(header_file)
                break

        # Clean up last page's header
        remove_file_silently(
            os.path.join(pages_directory, f"{label}_{current_page:04d}.json.hdr")
        )
        self.logger.info(f"  {label}: {len(all_records)} total across {current_page} pages")
        return all_records

    @staticmethod
    def _extract_next_page_url(header_file_path):
        """Extract the next page URL from the HTTP Link header.

        Qualys format: Link: <https://gateway.../images/list?page=2>;rel=next
        """
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


# =============================================================================
# PHASE 3: PARALLEL CONTAINER COUNT FETCHER
# =============================================================================

def fetch_container_counts_parallel(
    api_client, base_api_url, image_shas, container_scan_days,
    existing_counts, raw_directory, thread_count, logger
):
    """Fetch running container count for each image SHA using parallel threads.

    For each SHA, calls:
        GET /containers?filter=state:RUNNING AND imageSha:<SHA>
            AND lastVmScanDate:[now-3d...now]

    Response codes:
        200 → Parse JSON for container count
        204 → Zero running containers (valid, NOT an error)
        Other → Count as 0 and move on

    Thread safety:
        - All threads go through the GlobalRateLimiter before each call
        - Counts are saved to a shared dict with a lock
        - Progress is checkpointed to disk every 100 SHAs

    Args:
        existing_counts: Dict of already-fetched counts (for resume)
    """
    # Figure out which SHAs still need fetching
    shas_to_fetch = [sha for sha in image_shas if sha not in existing_counts]

    if not shas_to_fetch:
        logger.info(f"  All {len(image_shas)} image SHAs already cached")
        return existing_counts

    logger.info(
        f"  {len(shas_to_fetch)} to fetch, {len(existing_counts)} already cached "
        f"— using {thread_count} threads"
    )

    counts_file = os.path.join(raw_directory, "container_counts.json")
    completed_count = 0
    counter_lock = threading.Lock()
    start_time = time.time()

    def fetch_single_sha(sha):
        """Fetch container count for one SHA. Runs in a thread."""
        nonlocal completed_count

        container_api_url = (
            f"{base_api_url}/containers"
            f"?filter=state%3A%20%60RUNNING%60%20and%20imageSha%3A{sha}"
            f"%20and%20lastVmScanDate%3A%5Bnow-{container_scan_days}d%20...%20now%5D"
        )

        # Use SHA prefix + thread ID for temp file (avoids collisions)
        temp_file = os.path.join(
            raw_directory,
            f"_cc_{sha[:12]}_{threading.current_thread().ident}.json"
        )

        http_code = api_client.make_request(container_api_url, temp_file)
        container_count = 0

        if http_code == 200:
            # Response has data — parse the count
            try:
                response_data = json.load(open(temp_file))
                container_count = response_data.get("count", len(response_data.get("data", [])))
            except Exception:
                pass
        # http_code == 204 means zero containers (count stays 0)
        # http_code == 0 means request failed (count stays 0)

        remove_file_silently(temp_file)

        # Thread-safe update
        with counter_lock:
            existing_counts[sha] = container_count
            completed_count += 1

            # Progress log every 50 SHAs
            if completed_count % 50 == 0 or completed_count == 1 or completed_count == len(shas_to_fetch):
                elapsed = time.time() - start_time
                rate = elapsed / completed_count if completed_count > 0 else 1
                remaining_time = format_duration(int((len(shas_to_fetch) - completed_count) * rate))
                logger.info(
                    f"  Container counts: {completed_count}/{len(shas_to_fetch)} "
                    f"({remaining_time} remaining)"
                )

            # Checkpoint to disk every 100 SHAs
            if completed_count % 100 == 0:
                write_json_atomically(counts_file, existing_counts)

    # Run all fetches in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as pool:
        future_to_sha = {pool.submit(fetch_single_sha, sha): sha for sha in shas_to_fetch}
        for future in concurrent.futures.as_completed(future_to_sha):
            check_if_shutdown_requested()
            try:
                future.result()
            except Exception as error:
                logger.debug(f"  Thread error: {error}")

    # Final save
    write_json_atomically(counts_file, existing_counts)
    total_time = format_duration(int(time.time() - start_time))
    logger.info(f"  Done: {len(shas_to_fetch)} fetched in {total_time}")

    return existing_counts


# =============================================================================
# DATA PROCESSING — transform raw API data into report-ready structures
# =============================================================================

def extract_image_repositories(image_data):
    """Extract all (registry, repository, tag) entries from an image.

    Some images are pushed to multiple registries (e.g. both docker.io and ECR).
    Each registry/repo/tag gets its own row in the CSV.

    If registry is null in the repo list, we try to find it from repoDigests
    (a secondary field that sometimes has the registry).
    """
    repo_entries = image_data.get("repo") or []
    digest_entries = image_data.get("repoDigests") or []

    # Build a fallback lookup: repository name → registry from repoDigests
    registry_fallback = {}
    for digest in digest_entries:
        if digest.get("registry") and digest.get("repository"):
            registry_fallback[digest["repository"]] = digest["registry"]

    result = []
    for repo in repo_entries:
        registry = repo.get("registry")
        repository = convert_to_safe_string(repo.get("repository"))
        tag = convert_to_safe_string(repo.get("tag"))

        # If registry is null, try the fallback from repoDigests
        if not registry and repository:
            registry = registry_fallback.get(repository, "")

        result.append({
            "registry": convert_to_safe_string(registry),
            "repository": repository,
            "tag": tag,
        })

    # If no repos at all, return one empty entry so the image still gets a row
    return result if result else [{"registry": "", "repository": "", "tag": ""}]


def build_enriched_image_list(raw_images, eol_sha_set, container_counts, skip_containers):
    """Transform raw Qualys API records into enriched records for the report.

    Each enriched record contains:
    - All image metadata (ID, SHA, OS, architecture, dates, etc.)
    - EOL flag: True/False ONLY if the image has an operating system.
      If OS is empty (distroless/scratch images), EOL is left empty
      because evaluating EOL on a non-existent OS makes no sense.
    - Container count (from Container API, or "N/A" if skipped)
    - Full software and vulnerability lists (for CSV row generation)
    """
    enriched = []

    for image in raw_images:
        image_sha = image.get("sha", "")
        vulnerabilities = image.get("vulnerabilities") or []
        softwares = image.get("softwares") or []
        operating_system = convert_to_safe_string(image.get("operatingSystem"))

        # EOL evaluation: only meaningful when OS is known.
        # Distroless/scratch images have no OS → EOL should be empty, not False.
        if operating_system:
            eol_base_os = image_sha in eol_sha_set  # True or False
        else:
            eol_base_os = ""  # empty — cannot evaluate EOL without an OS

        enriched.append({
            "image_id":           convert_to_safe_string(image.get("imageId")),
            "image_sha":          image_sha,
            "operating_system":   operating_system,
            "eol_base_os":        eol_base_os,
            "architecture":       convert_to_safe_string(image.get("architecture")),
            "created":            convert_epoch_ms_to_iso(image.get("created")),
            "last_scanned":       convert_epoch_ms_to_iso(image.get("lastScanned")),
            "scan_types":         image.get("scanTypes") or [],
            "source":             image.get("source") or [],
            "repositories":       extract_image_repositories(image),
            "risk_score":         image.get("riskScore"),
            "qds_score":          image.get("maxQdsScore"),
            "qds_severity":       convert_to_safe_string(image.get("qdsSeverity")),
            "vulnerability_count": len(vulnerabilities),
            "container_count":    container_counts.get(image_sha, "N/A") if not skip_containers else "N/A",
            "vulnerabilities":    vulnerabilities,
            "softwares":          softwares,
        })

    return enriched


# =============================================================================
# CSV REPORT — 32 columns, fully denormalized
#
# The CSV has one row per (image × repo × vulnerability/software).
# This means image-level data is repeated, but you can filter in Excel
# by any column without needing pivot tables or VLOOKUPs.
#
# EOL_Base_OS logic:
#   - Image HAS an OS → True or False based on EOL API match
#   - Image has NO OS (distroless/scratch) → empty (not evaluated)
#
# Row generation (for each image × each registry/repo/tag):
#   Pass 1: One row per vulnerability × affected software
#   Pass 2: One row per installed software NOT covered by a vulnerability
#   Pass 3: One row for bare images (no software, no vulns)
# =============================================================================

CSV_HEADERS = [
    # Image columns (17)
    "Image_ID", "Image_SHA", "Operating_System", "EOL_Base_OS", "Architecture",
    "Image_Created", "Image_Last_Scanned", "Image_Scan_Types", "Image_Source",
    "Registry", "Repository", "Image_Tag",
    "Risk_Score", "Max_QDS_Score", "QDS_Severity",
    "Total_Vulnerabilities_On_Image", "Running_Container_Count",

    # Software columns (8)
    "Software_Name", "Software_Installed_Version", "Software_Fix_Version",
    "Software_Package_Path",
    "Software_Lifecycle_Stage", "Software_GA_Date", "Software_EOL_Date", "Software_EOS_Date",

    # Vulnerability columns (7)
    "Vuln_QID", "Vuln_Scan_Type", "Vuln_Type_Detected", "Vuln_First_Found",
    "Vuln_Affected_Software_Name", "Vuln_Affected_Software_Version", "Vuln_Fix_Version",
]

IMAGE_COLUMN_COUNT    = 17
SOFTWARE_COLUMN_COUNT = 8   # was 7, added Package_Path
VULN_COLUMN_COUNT     = 7
EMPTY_SOFTWARE_COLS   = [""] * SOFTWARE_COLUMN_COUNT
EMPTY_VULN_COLS       = [""] * VULN_COLUMN_COUNT


def build_image_columns(image, repo):
    """Build the 17 image-level columns for one CSV row."""
    return [
        image["image_id"],
        image["image_sha"],
        image["operating_system"],
        image["eol_base_os"],
        image["architecture"],
        image["created"],
        image["last_scanned"],
        " | ".join(convert_to_safe_string(s) for s in image["scan_types"]),
        " | ".join(convert_to_safe_string(s) for s in image["source"]),
        repo["registry"],
        repo["repository"],
        repo["tag"],
        convert_to_safe_string(image["risk_score"]),
        convert_to_safe_string(image["qds_score"]),
        image["qds_severity"],
        image["vulnerability_count"],
        image["container_count"],
    ]


def build_software_columns(software):
    """Build the 8 software-level columns for one CSV row."""
    lifecycle = software.get("lifecycle") or {}
    return [
        convert_to_safe_string(software.get("name")),
        convert_to_safe_string(software.get("version")),
        convert_to_safe_string(software.get("fixVersion")),
        convert_to_safe_string(software.get("packagePath")),  # e.g. "app/bin/myapp" or null
        convert_to_safe_string(lifecycle.get("stage")),
        convert_epoch_ms_to_iso(lifecycle.get("gaDate")),
        convert_epoch_ms_to_iso(lifecycle.get("eolDate")),
        convert_epoch_ms_to_iso(lifecycle.get("eosDate")),
    ]


def build_vulnerability_columns(vulnerability, affected_software):
    """Build the 7 vulnerability-level columns for one CSV row."""
    return [
        convert_to_safe_string(vulnerability.get("qid")),
        " | ".join(convert_to_safe_string(s) for s in (vulnerability.get("scanType") or [])),
        convert_to_safe_string(vulnerability.get("typeDetected")),
        convert_epoch_ms_to_iso(vulnerability.get("firstFound")),
        convert_to_safe_string(affected_software.get("name")),
        convert_to_safe_string(affected_software.get("version")),
        convert_to_safe_string(affected_software.get("fixVersion")),
    ]


def generate_csv_report(enriched_images, output_path, logger):
    """Write the unified CSV report. Uses atomic write (temp → rename).

    Returns the total number of data rows written.
    """
    temp_path = output_path + ".tmp"
    total_rows = 0

    with open(temp_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(CSV_HEADERS)

        for image in enriched_images:
            # Build software lookup ONCE per image (not per repo)
            software_by_name_version = {}
            for sw in image["softwares"]:
                key = (convert_to_safe_string(sw.get("name")),
                       convert_to_safe_string(sw.get("version")))
                software_by_name_version[key] = sw

            # Each registry/repo/tag gets its own set of rows
            for repo in image["repositories"]:
                image_cols = build_image_columns(image, repo)
                assert len(image_cols) == IMAGE_COLUMN_COUNT

                # Track which softwares were already written via vulnerability rows
                softwares_written_via_vulns = set()

                # PASS 1: Vulnerability rows
                for vuln in image["vulnerabilities"]:
                    affected_softwares = vuln.get("software") or [{}]
                    for affected_sw in affected_softwares:
                        sw_key = (convert_to_safe_string(affected_sw.get("name")),
                                  convert_to_safe_string(affected_sw.get("version")))

                        # Try to match vuln's affected software to installed software
                        matched_software = software_by_name_version.get(sw_key)
                        sw_cols = build_software_columns(matched_software) if matched_software else EMPTY_SOFTWARE_COLS
                        vuln_cols = build_vulnerability_columns(vuln, affected_sw)

                        row = image_cols + sw_cols + vuln_cols
                        assert len(row) == len(CSV_HEADERS)
                        writer.writerow(row)
                        total_rows += 1

                        if matched_software:
                            softwares_written_via_vulns.add(sw_key)

                # PASS 2: Software-only rows (not covered by vulns)
                for sw in image["softwares"]:
                    sw_key = (convert_to_safe_string(sw.get("name")),
                              convert_to_safe_string(sw.get("version")))
                    if sw_key not in softwares_written_via_vulns:
                        row = image_cols + build_software_columns(sw) + EMPTY_VULN_COLS
                        assert len(row) == len(CSV_HEADERS)
                        writer.writerow(row)
                        total_rows += 1

                # PASS 3: Bare image (no software, no vulns)
                if not image["softwares"] and not image["vulnerabilities"]:
                    row = image_cols + EMPTY_SOFTWARE_COLS + EMPTY_VULN_COLS
                    assert len(row) == len(CSV_HEADERS)
                    writer.writerow(row)
                    total_rows += 1

    # Atomic rename
    os.replace(temp_path, output_path)
    logger.info(f"  CSV: {output_path} ({total_rows:,} rows)")
    return total_rows


def generate_json_report(enriched_images, output_path, logger):
    """Write the full JSON report."""
    write_json_atomically(output_path, {
        "generatedAt": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "totalImages": len(enriched_images),
        "eolImages": sum(1 for img in enriched_images if img["eol_base_os"]),
        "images": enriched_images,
    })
    logger.info(f"  JSON: {output_path}")


# =============================================================================
# COMMAND-LINE ARGUMENT PARSING
# =============================================================================

def parse_command_line_arguments():
    parser = argparse.ArgumentParser(
        prog="qualys_cs_report",
        description=f"Qualys Container Security Image Report Generator v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Basic run — images in use last 30 days
  export QUALYS_ACCESS_TOKEN="eyJ..."
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com

  # Custom filter — only Ubuntu images
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com \\
      -f "operatingSystem:Ubuntu"

  # Fast run — skip container counts
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --skip-containers

  # More threads, faster API calls
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --concurrency 10 --cps 3

  # Dry run — preview config, no API calls
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --dry-run

  # Force fresh run (ignore cached data)
  python3 qualys_cs_report.py -g https://gateway.qg2.apps.qualys.com --force
""",
    )

    env = os.environ.get

    # Connection
    parser.add_argument("-g", "--gateway", default=env("QUALYS_GATEWAY", DEFAULT_GATEWAY),
                        help="Qualys gateway URL")
    parser.add_argument("-t", "--token", default=env("QUALYS_ACCESS_TOKEN", ""),
                        help="Access token (default: $QUALYS_ACCESS_TOKEN)")

    # Query parameters
    parser.add_argument("-l", "--limit", type=int,
                        default=int(env("QUALYS_LIMIT", DEFAULT_PAGE_LIMIT)),
                        help=f"Results per page, 1-250 (default: {DEFAULT_PAGE_LIMIT})")
    parser.add_argument("-d", "--days", type=int,
                        default=int(env("QUALYS_DAYS", DEFAULT_IMAGE_LOOKBACK_DAYS)),
                        help=f"Image lookback days (default: {DEFAULT_IMAGE_LOOKBACK_DAYS})")
    parser.add_argument("-D", "--container-scan-days", type=int,
                        default=int(env("QUALYS_CONTAINER_SCAN_DAYS", DEFAULT_CONTAINER_SCAN_DAYS)),
                        help=f"Container scan lookback (default: {DEFAULT_CONTAINER_SCAN_DAYS})")
    parser.add_argument("-f", "--filter", default=env("QUALYS_FILTER", ""),
                        help="Extra filter appended with AND (e.g. 'operatingSystem:Ubuntu')")

    # Output
    parser.add_argument("-o", "--output-dir",
                        default=env("QUALYS_OUTPUT_DIR", "./qualys_report_output"),
                        help="Output directory")

    # Behavior
    parser.add_argument("--skip-containers", action="store_true",
                        default=env("QUALYS_SKIP_CONTAINER_COUNT", "").lower() == "true",
                        help="Skip container count API calls (much faster)")
    parser.add_argument("--force", action="store_true",
                        help="Ignore checkpoint, start fresh")

    # Performance tuning
    parser.add_argument("--concurrency", type=int,
                        default=int(env("QUALYS_CONCURRENCY", DEFAULT_THREAD_COUNT)),
                        help=f"Parallel threads for container counts (default: {DEFAULT_THREAD_COUNT})")
    parser.add_argument("--cps", type=int,
                        default=int(env("QUALYS_CPS", DEFAULT_CALLS_PER_SECOND)),
                        help=f"Max API calls per second (default: {DEFAULT_CALLS_PER_SECOND})")
    parser.add_argument("-r", "--retries", type=int, default=DEFAULT_MAX_RETRIES,
                        help=f"Max retries per failed call (default: {DEFAULT_MAX_RETRIES})")
    parser.add_argument("-C", "--curl-extra", default=env("QUALYS_CURL_EXTRA", ""),
                        help="Extra curl arguments (e.g. '--proxy http://proxy:8080')")

    # Output control
    parser.add_argument("-v", "--verbose", action="store_true", help="Show debug messages")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress console output")
    parser.add_argument("--dry-run", action="store_true", help="Show config, no API calls")

    return parser.parse_args()


# =============================================================================
# MAIN — orchestrates all 5 phases
# =============================================================================

def main():
    args = parse_command_line_arguments()
    start_time = time.time()

    # ── Validate inputs ──
    if not args.token:
        print("ERROR: No access token. Set QUALYS_ACCESS_TOKEN or use -t <token>",
              file=sys.stderr)
        sys.exit(1)

    if not args.gateway.startswith("https://"):
        print("ERROR: Gateway must use HTTPS", file=sys.stderr)
        sys.exit(1)

    # ── Setup directories, logging, lock file ──
    output_dir = args.output_dir
    pages_dir = os.path.join(output_dir, "pages")
    raw_dir = os.path.join(output_dir, "raw")
    os.makedirs(pages_dir, exist_ok=True)
    os.makedirs(raw_dir, exist_ok=True)

    logger, log_file_path = setup_logging(output_dir, args.verbose, args.quiet)
    acquire_lock_file(output_dir, args.force)

    # ── Build API URLs ──
    base_api_url = f"{args.gateway.rstrip('/')}/csapi/{DEFAULT_API_VERSION}"

    image_filter = build_image_api_filter(args.days, args.filter)
    eol_filter = build_image_api_filter(
        args.days,
        "vulnerabilities.title%3AEOL" + (
            f"%20and%20{args.filter.replace(' ', '%20')}" if args.filter else ""
        )
    )

    image_list_url = f"{base_api_url}/images/list?filter={image_filter}&limit={args.limit}"
    eol_list_url = f"{base_api_url}/images/list?filter={eol_filter}&limit={args.limit}"

    # ── Print banner ──
    logger.info(f"Qualys CS Report Generator v{VERSION}")
    logger.info(f"Gateway:     {args.gateway}")
    logger.info(f"Output:      {output_dir}")
    logger.info(f"Params:      limit={args.limit} days={args.days} container_days={args.container_scan_days}")
    logger.info(f"Performance: {args.concurrency} threads, {args.cps} calls/sec, {args.retries} retries")
    if args.filter:
        logger.info(f"Filter:      {args.filter}")

    # ── Dry run — show config and exit ──
    if args.dry_run:
        logger.info(f"\nDRY RUN — no API calls will be made")
        logger.info(f"Image URL:     {image_list_url}")
        logger.info(f"EOL URL:       {eol_list_url}")
        logger.info(f"Container URL: {base_api_url}/containers?filter=state:RUNNING AND imageSha:<SHA>")
        return

    # ── Initialize checkpoint, rate limiter, API client ──
    checkpoint = CheckpointManager(output_dir, generate_config_fingerprint(args))

    if checkpoint.is_phase_complete("complete") and not args.force:
        logger.info("Previous run already complete. Use --force for a fresh run.")
        return
    if args.force:
        checkpoint.clear_all()

    rate_limiter = GlobalRateLimiter(args.cps, logger)
    api_client = QualysApiClient(
        gateway_url=args.gateway,
        access_token=args.token,
        max_retries=args.retries,
        connect_timeout=DEFAULT_CONNECT_TIMEOUT,
        request_timeout=DEFAULT_REQUEST_TIMEOUT,
        extra_curl_args=args.curl_extra,
        rate_limiter=rate_limiter,
        logger=logger,
    )

    # ================================================================
    # PHASE 1: Fetch all images
    # ================================================================
    all_images_cache = os.path.join(raw_dir, "all_images.json")

    if checkpoint.is_phase_complete("images"):
        logger.info("\n[Phase 1] Images — loaded from cache")
        all_images = json.load(open(all_images_cache))
    else:
        logger.info("\n[Phase 1] Fetching all images...")
        all_images = api_client.fetch_all_pages(image_list_url, pages_dir, "img", args.limit)
        write_json_atomically(all_images_cache, all_images)
        checkpoint.mark_complete("images")

    logger.info(f"  Total: {len(all_images)} images")

    if len(all_images) == 0:
        logger.warning("  WARNING: 0 images returned. Check your gateway, token, and filter.")

    # ================================================================
    # PHASE 2: Fetch EOL images and compare SHAs
    # ================================================================
    eol_cache = os.path.join(raw_dir, "eol_shas.json")

    if checkpoint.is_phase_complete("eol"):
        logger.info("\n[Phase 2] EOL images — loaded from cache")
        eol_image_shas = set(json.load(open(eol_cache)))
    else:
        logger.info("\n[Phase 2] Fetching EOL base OS images...")
        eol_images = api_client.fetch_all_pages(eol_list_url, pages_dir, "eol", args.limit)
        eol_image_shas = set(img["sha"] for img in eol_images if img.get("sha"))
        write_json_atomically(eol_cache, list(eol_image_shas))
        checkpoint.mark_complete("eol")

    logger.info(f"  EOL Base OS images: {len(eol_image_shas)}")

    # ================================================================
    # PHASE 3: Fetch container counts (parallel)
    # ================================================================
    container_counts_cache = os.path.join(raw_dir, "container_counts.json")
    container_counts = {}

    if args.skip_containers:
        logger.info("\n[Phase 3] Container counts — skipped (--skip-containers)")

    elif checkpoint.is_phase_complete("containers"):
        logger.info("\n[Phase 3] Container counts — loaded from cache")
        container_counts = json.load(open(container_counts_cache))

    else:
        logger.info("\n[Phase 3] Fetching container counts (parallel)...")
        unique_shas = list(set(img["sha"] for img in all_images if img.get("sha")))

        # Load partial progress if available (resume support)
        if os.path.exists(container_counts_cache):
            try:
                container_counts = json.load(open(container_counts_cache))
            except (json.JSONDecodeError, KeyError):
                container_counts = {}

        container_counts = fetch_container_counts_parallel(
            api_client, base_api_url, unique_shas, args.container_scan_days,
            container_counts, raw_dir, args.concurrency, logger,
        )
        checkpoint.mark_complete("containers")

    # ================================================================
    # PHASE 4: Generate reports
    # ================================================================
    logger.info("\n[Phase 4] Generating reports...")

    enriched_images = build_enriched_image_list(
        all_images, eol_image_shas, container_counts, args.skip_containers
    )

    csv_row_count = generate_csv_report(
        enriched_images,
        os.path.join(output_dir, "qualys_cs_unified_report.csv"),
        logger,
    )

    generate_json_report(
        enriched_images,
        os.path.join(output_dir, "images_full_report.json"),
        logger,
    )

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
        "eol_images": sum(1 for img in enriched_images if img["eol_base_os"]),
        "total_vulnerabilities": sum(img["vulnerability_count"] for img in enriched_images),
        "csv_rows": csv_row_count,
        "csv_columns": len(CSV_HEADERS),
        "duration": format_duration(total_duration),
        "api_calls": api_client.total_api_calls,
        "retries": api_client.total_retries,
        "errors": api_client.total_errors,
        "throttle_events": rate_limiter.total_throttle_events,
        "throttle_seconds": rate_limiter.total_throttle_seconds,
        "concurrency": args.concurrency,
        "calls_per_second": args.cps,
    }

    write_json_atomically(os.path.join(output_dir, "run_summary.json"), run_summary)
    checkpoint.mark_complete("complete")

    # ── Final output ──
    logger.info(f"\n{'=' * 55}")
    logger.info(f"  DONE in {format_duration(total_duration)}")
    logger.info(f"  Images: {run_summary['total_images']} | EOL: {run_summary['eol_images']} | Vulns: {run_summary['total_vulnerabilities']}")
    logger.info(f"  CSV: {csv_row_count:,} rows × {len(CSV_HEADERS)} cols | API: {api_client.total_api_calls} calls")
    logger.info(f"  Output: {output_dir}/")
    logger.info(f"{'=' * 55}")


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    main()
