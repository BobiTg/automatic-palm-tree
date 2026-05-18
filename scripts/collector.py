import base64
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from urllib.parse import parse_qs, unquote, urlparse

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHANNEL_URL = "https://t.me/s/Billy_VPN_Emerald"
KEYS_FILE = "keys/all_keys.txt"
STATE_FILE = "keys/state.json"
DAYS_INIT = 15
MAX_PAGES = 60  # max pages to paginate (60 × ~20 msgs = ~1200 msgs)
SUB_TIMEOUT = 5  # seconds per User-Agent attempt for subscriptions
FETCH_TIMEOUT = 8  # seconds for channel page fetch
SUB_WORKERS = 20  # parallel threads for subscription fetching
TCP_WORKERS = 200  # parallel threads for TCP checks
TCP_TIMEOUT = 2.0  # seconds for TCP connect check

# Source priority (lower = better, appears first in output)
SRC_DIRECT = 0  # key written directly in channel message
SRC_REMNAWAVE = 1  # from panel/remnawave subscription URL
SRC_GITHUB = 2  # from raw.githubusercontent / gist
SRC_OTHER = 3  # any other subscription URL

GITHUB_HOSTS = {
    "raw.githubusercontent.com",
    "gist.github.com",
    "gist.githubusercontent.com",
}

KEY_PATTERN = re.compile(
    r'(vless|vmess|ss|trojan|hy2|hysteria2|tuic)://[^\s\n\r<>"\'`]+',
    re.IGNORECASE,
)

USER_AGENTS = [
    "Happ/1.9.5 CFNetwork/1568.200.51 Darwin/24.1.0",
    "V2RayTun/2.1 CFNetwork/1568.200.51 Darwin/24.1.0",
    "Hiddify/2.0.5 CFNetwork/1568.100.3 Darwin/24.0.0",
    "clash-verge/1.7.7",
    "ClashforWindows/0.20.39",
    "v2rayNG/1.9.1",
    "sing-box/1.10.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

VPN_PROTOCOLS = ["vless", "vmess", "ss", "trojan", "hy2", "hysteria2", "tuic"]

# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------


def load_state() -> dict:
    """Load state from STATE_FILE; return default if missing or corrupt."""
    os.makedirs("keys", exist_ok=True)
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            print(f"[WARN] Could not load state: {exc}")
    return {"last_message_id": 0}


def save_state(state: dict) -> None:
    """Persist state to STATE_FILE."""
    os.makedirs("keys", exist_ok=True)
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
    except Exception as exc:
        print(f"[WARN] Could not save state: {exc}")


# ---------------------------------------------------------------------------
# Key file helpers
# ---------------------------------------------------------------------------


def load_existing_keys() -> set:
    """Return a set of VPN keys already saved to KEYS_FILE."""
    os.makedirs("keys", exist_ok=True)
    if not os.path.exists(KEYS_FILE):
        return set()
    try:
        with open(KEYS_FILE, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as exc:
        print(f"[WARN] Could not read existing keys: {exc}")
        return set()


def save_keys(keys_set: set) -> None:
    """Sort keys by protocol prefix and write to KEYS_FILE, one per line."""
    os.makedirs("keys", exist_ok=True)

    def protocol_order(key: str) -> str:
        for proto in VPN_PROTOCOLS:
            if key.lower().startswith(proto + "://"):
                return proto
        return "zzz"

    sorted_keys = sorted(keys_set, key=lambda k: (protocol_order(k), k))
    try:
        with open(KEYS_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted_keys) + ("\n" if sorted_keys else ""))
    except Exception as exc:
        print(f"[ERROR] Could not save keys: {exc}")


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _log(level: str, msg: str) -> None:
    ts = datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{ts}][{level}] {msg}", flush=True)


def fetch_page(url: str) -> str | None:
    """Fetch a URL with browser headers; retry up to 2 times on failure."""
    headers = {
        "User-Agent": BROWSER_UA,
        "Accept-Language": "ru-RU,ru;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    for attempt in range(1, 3):
        try:
            resp = requests.get(
                url, headers=headers, timeout=FETCH_TIMEOUT, allow_redirects=True
            )
            if resp.status_code == 200:
                return resp.text
            _log(
                "WARN",
                f"fetch_page {url} → HTTP {resp.status_code} (attempt {attempt})",
            )
        except Exception as exc:
            _log("WARN", f"fetch_page {url} attempt {attempt} error: {exc}")
        if attempt < 2:
            time.sleep(1)
    return None


def _try_one_ua(url: str, ua: str) -> str | None:
    """Single attempt: one URL + one User-Agent. Returns text or None."""
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": ua},
            timeout=SUB_TIMEOUT,
            allow_redirects=True,
        )
        if resp.status_code == 200 and len(resp.text) > 30:
            return resp.text
    except Exception:
        pass
    return None


def fetch_subscription(url: str) -> str | None:
    """Try ALL User-Agents in PARALLEL, return first winner."""
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=len(USER_AGENTS)) as ex:
        futures = {ex.submit(_try_one_ua, url, ua): ua for ua in USER_AGENTS}
        result = None
        for fut in as_completed(futures):
            text = fut.result()
            if text and result is None:
                result = text
                # cancel remaining (best-effort)
                for f in futures:
                    f.cancel()
    elapsed = time.time() - t0
    ua_short = "OK" if result else "FAIL"
    _log(
        "INFO" if result else "WARN",
        f"  sub {ua_short} in {elapsed:.1f}s ({len(result) if result else 0} bytes) <- {url[:60]}",
    )
    return result


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def parse_channel_page(html: str) -> list[dict]:
    """Parse t.me/s HTML; return list of message dicts."""
    soup = BeautifulSoup(html, "lxml")
    messages = []

    for widget in soup.select(".tgme_widget_message"):
        # --- message id ---
        data_post = widget.get("data-post", "")
        try:
            msg_id = int(data_post.rsplit("/", 1)[-1])
        except (ValueError, IndexError):
            continue

        # --- text ---
        text_el = widget.select_one(".tgme_widget_message_text")
        text = text_el.get_text("\n") if text_el else ""

        # --- links from <a> tags inside message text ---
        links: list[str] = []
        if text_el:
            for a in text_el.find_all("a", href=True):
                href = a["href"].strip()
                if href:
                    links.append(href)

        # --- datetime ---
        time_el = widget.select_one("time[datetime]")
        date_str = time_el["datetime"] if time_el else ""

        messages.append({"id": msg_id, "text": text, "links": links, "date": date_str})

    return messages


# ---------------------------------------------------------------------------
# Message collection
# ---------------------------------------------------------------------------


def _parse_date(date_str: str) -> datetime | None:
    """Parse ISO-8601 datetime string (with optional timezone offset)."""
    if not date_str:
        return None
    # Telegram uses format: 2024-01-15T12:34:56+00:00  or  ...Z
    date_str = date_str.replace("Z", "+00:00")
    try:
        # Python 3.7+ fromisoformat doesn't handle colon in offset on older builds
        return datetime.fromisoformat(date_str).replace(tzinfo=None)
    except Exception:
        # Fallback: strip timezone and try again
        try:
            return datetime.fromisoformat(date_str[:19])
        except Exception:
            return None


def collect_messages(
    since_days: int | None = None, after_id: int | None = None
) -> list[dict]:
    """
    Collect messages from the Telegram channel public preview.

    - since_days: go back this many days from now
    - after_id:   collect only messages with id > after_id
    Returns messages sorted by id ascending.
    """
    cutoff_date = datetime.utcnow() - timedelta(days=since_days) if since_days else None

    all_messages: list[dict] = []
    seen_ids: set[int] = set()
    next_before: int | None = None
    stop = False
    page_num = 0

    while not stop:
        if page_num >= MAX_PAGES:
            _log("WARN", f"Reached MAX_PAGES={MAX_PAGES}, stopping pagination")
            break
        url = (
            CHANNEL_URL
            if next_before is None
            else f"{CHANNEL_URL}?before={next_before}"
        )
        _log("INFO", f"Fetching page {page_num + 1}: {url}")
        html = fetch_page(url)
        page_num += 1
        if not html:
            _log("WARN", "Empty page response, stopping.")
            break

        page_messages = parse_channel_page(html)
        if not page_messages:
            _log("INFO", "No messages on page, stopping.")
            break

        new_on_page = 0
        for msg in page_messages:
            if msg["id"] in seen_ids:
                continue
            seen_ids.add(msg["id"])

            # after_id mode: stop when we reach already-seen messages
            if after_id is not None and msg["id"] <= after_id:
                stop = True
                continue

            # since_days mode: stop when message is older than cutoff
            if cutoff_date is not None:
                msg_date = _parse_date(msg["date"])
                if msg_date and msg_date < cutoff_date:
                    stop = True
                    continue

            all_messages.append(msg)
            new_on_page += 1

        _log(
            "INFO",
            f"  Page {page_num}: +{new_on_page} new msgs (total so far: {len(all_messages)})",
        )
        if new_on_page == 0:
            break

        # Prepare next page (paginate backwards)
        min_id = min(m["id"] for m in page_messages)
        if next_before is not None and min_id >= next_before:
            # No progress
            break
        next_before = min_id

        if not stop:
            time.sleep(0.8)

    all_messages.sort(key=lambda m: m["id"])
    return all_messages


# ---------------------------------------------------------------------------
# Key extraction
# ---------------------------------------------------------------------------


def extract_keys(text: str) -> list[str]:
    """Apply KEY_PATTERN to text; clean trailing punctuation from matches."""
    raw_matches = KEY_PATTERN.findall(text)  # findall with groups returns tuples
    # Use finditer for full match strings
    keys = []
    for match in KEY_PATTERN.finditer(text):
        key = match.group(0)
        # Strip trailing punctuation that might have been captured
        key = key.rstrip(")],.'\"`;>")
        if key:
            keys.append(key)
    return keys


def extract_subscription_urls(text: str, links: list[str]) -> list[str]:
    """
    Extract subscription URLs from message text and link list.
    Filters out direct VPN key links, t.me links, images, etc.
    Handles yax.nenadoblokirowatgnidda.ru proxy URLs.
    """
    # Pull URLs from plain text too
    url_pattern = re.compile(r'https?://[^\s\n\r<>"\'`]+', re.IGNORECASE)
    text_urls = url_pattern.findall(text)

    candidates = list(links) + text_urls
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_candidates: list[str] = []
    for u in candidates:
        u = u.strip().rstrip(")],.'\"`;>")
        if u and u not in seen:
            seen.add(u)
            unique_candidates.append(u)

    image_ext = {".jpg", ".jpeg", ".png", ".gif", ".mp4", ".webp", ".svg", ".ico"}

    result: list[str] = []
    result_seen: set[str] = set()

    def add_url(u: str) -> None:
        if u and u not in result_seen:
            result_seen.add(u)
            result.append(u)

    for url in unique_candidates:
        # Skip direct VPN keys
        if any(url.lower().startswith(p + "://") for p in VPN_PROTOCOLS):
            continue

        # Must be http(s)
        if not url.startswith("http://") and not url.startswith("https://"):
            continue

        parsed = urlparse(url)
        host = parsed.hostname or ""

        # Skip t.me links
        if "t.me" in host or "telegram.me" in host:
            continue

        # Skip image/video/emoji CDN URLs
        if any(kw in host for kw in ["cdn-telegram", "cdn.telegram", "emoji"]):
            continue

        # Skip by file extension
        path_lower = parsed.path.lower()
        if any(path_lower.endswith(ext) for ext in image_ext):
            continue

        # Handle yax proxy URLs
        if "nenadoblokirowatgnidda.ru" in host and "url=" in parsed.query:
            qs = parse_qs(parsed.query)
            inner_urls = qs.get("url", [])
            for inner_raw in inner_urls:
                inner = unquote(inner_raw)
                add_url(url)  # also try original proxy URL
                add_url(inner)  # and the inner decoded URL
            continue

        add_url(url)

    return result


# ---------------------------------------------------------------------------
# Content decoding
# ---------------------------------------------------------------------------


def decode_content(content: str) -> str:
    """Try to base64-decode content; return as-is if it already has VPN keys."""
    content = content.strip()
    # If already contains VPN keys directly, return as-is
    if any(p + "://" in content for p in VPN_PROTOCOLS):
        return content
    # Try base64 decode
    try:
        padded = content + "=" * (4 - len(content) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if any(p + "://" in decoded for p in VPN_PROTOCOLS):
            return decoded
    except Exception:
        pass
    return content


# ---------------------------------------------------------------------------
# Message processing
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Source classification
# ---------------------------------------------------------------------------


def classify_url(url: str) -> int:
    """Return source priority for a subscription URL."""
    host = urlparse(url).hostname or ""
    if host in GITHUB_HOSTS:
        return SRC_GITHUB
    return SRC_REMNAWAVE  # panels, CDNs, etc.


# ---------------------------------------------------------------------------
# TCP connectivity check
# ---------------------------------------------------------------------------


def _extract_host_port(key: str) -> tuple[str, int] | None:
    """Extract (host, port) from a VPN key string."""
    try:
        scheme, rest = key.split("://", 1)
        scheme = scheme.lower()

        if scheme == "vmess":
            # vmess is base64-encoded JSON
            padding = rest + "=" * (4 - len(rest) % 4)
            data = json.loads(
                base64.b64decode(padding).decode("utf-8", errors="ignore")
            )
            host = data.get("add", "")
            port = int(data.get("port", 0))
            return (host, port) if host and port else None

        # All others: scheme://[userinfo@]host:port[/path][?query][#frag]
        # Strip userinfo
        if "@" in rest:
            rest = rest.split("@", 1)[1]
        # Strip path/query/fragment
        rest = rest.split("/")[0].split("?")[0].split("#")[0]
        # IPv6
        if rest.startswith("["):
            bracket_end = rest.index("]")
            host = rest[1:bracket_end]
            port = int(rest[bracket_end + 2 :])
        else:
            host, port_str = rest.rsplit(":", 1)
            port = int(port_str)
        return (host, port) if host and 0 < port < 65536 else None
    except Exception:
        return None


def tcp_check(key: str) -> bool:
    """Return True if the key's host:port is reachable via TCP."""
    hp = _extract_host_port(key)
    if not hp:
        return False
    host, port = hp
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


def tcp_check_all(keys: list[str]) -> dict[str, bool]:
    """TCP-check all keys in parallel. Returns {key: alive}."""
    _log(
        "INFO",
        f"TCP-checking {len(keys)} keys ({TCP_WORKERS} workers, {TCP_TIMEOUT}s timeout)...",
    )
    t0 = time.time()
    results: dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        fut_map = {ex.submit(tcp_check, k): k for k in keys}
        for fut in as_completed(fut_map):
            key = fut_map[fut]
            try:
                results[key] = fut.result()
            except Exception:
                results[key] = False
    alive = sum(1 for v in results.values() if v)
    _log("INFO", f"TCP done in {time.time() - t0:.1f}s: {alive}/{len(keys)} alive")
    return results


# ---------------------------------------------------------------------------
# Fetch + extract helpers
# ---------------------------------------------------------------------------


def _fetch_and_extract(url: str) -> tuple[set, int]:
    """Fetch one subscription URL, extract keys, return (keys_set, src_priority)."""
    src = classify_url(url)
    try:
        raw = fetch_subscription(url)
        if raw:
            decoded = decode_content(raw)
            return set(extract_keys(decoded)), src
    except Exception as exc:
        _log("WARN", f"  sub error {url[:60]}: {exc}")
    return set(), src


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def save_keys_sorted(key_source: dict[str, int], alive: dict[str, bool]) -> None:
    """
    Save keys to KEYS_FILE sorted by:
      1. alive first, dead last
      2. within alive: SRC_DIRECT → SRC_REMNAWAVE → SRC_GITHUB → SRC_OTHER
      3. within same group: alphabetical
    Writes section headers as comments.
    """
    os.makedirs("keys", exist_ok=True)

    groups: dict[tuple[bool, int], list[str]] = {}
    for key, src in key_source.items():
        is_alive = alive.get(key, False)
        bucket = (not is_alive, src)  # False sorts before True → alive first
        groups.setdefault(bucket, []).append(key)

    src_labels = {
        SRC_DIRECT: "канал (прямые)",
        SRC_REMNAWAVE: "подписки (panel/remnawave)",
        SRC_GITHUB: "подписки (github)",
        SRC_OTHER: "подписки (прочие)",
    }

    lines: list[str] = []
    prev_alive_state: bool | None = None
    prev_src: int | None = None

    for dead, src in sorted(groups.keys()):
        is_alive = not dead
        keys_in_group = sorted(groups[(dead, src)])

        if prev_alive_state != is_alive:
            if lines:
                lines.append("")
            lines.append("# " + ("=" * 60))
            lines.append(
                "# " + ("✅ РАБОЧИЕ" if is_alive else "❌ НЕРАБОЧИЕ (TCP недоступны)")
            )
            lines.append("# " + ("=" * 60))
            prev_alive_state = is_alive
            prev_src = None

        if prev_src != src:
            lines.append("")
            lines.append(
                f"# --- {src_labels.get(src, 'прочие')} ({len(keys_in_group)} шт) ---"
            )
            prev_src = src

        lines.extend(keys_in_group)

    with open(KEYS_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    t_start = time.time()
    mode = sys.argv[1] if len(sys.argv) > 1 else "update"
    _log("INFO", f"=== VPN Collector started | mode={mode} ===")

    os.makedirs("keys", exist_ok=True)

    state = load_state()
    # key_source: {key_str: src_priority}
    existing_raw = load_existing_keys()  # set[str] — keys without comments
    existing_key_source: dict[str, int] = {
        k: SRC_OTHER for k in existing_raw if not k.startswith("#")
    }
    _log("INFO", f"Existing keys loaded: {len(existing_key_source)}")

    if mode == "init":
        _log("INFO", f"Collecting last {DAYS_INIT} days (max {MAX_PAGES} pages)")
        messages = collect_messages(since_days=DAYS_INIT)
    else:
        last_id = state.get("last_message_id", 0)
        _log("INFO", f"Collecting messages after id={last_id}")
        messages = collect_messages(after_id=last_id)

    _log("INFO", f"Processing {len(messages)} messages")

    # --- Step 1: collect direct keys and sub URLs ---
    _log("INFO", "Step 1: collecting direct keys & sub URLs...")
    new_key_source: dict[str, int] = {}  # key → best source priority

    all_sub_urls: dict[str, int] = {}  # url → src_priority
    for msg in messages:
        # direct keys
        for k in extract_keys(msg["text"]):
            new_key_source[k] = min(new_key_source.get(k, 99), SRC_DIRECT)
        # sub URLs
        for url in extract_subscription_urls(msg["text"], msg["links"]):
            src = classify_url(url)
            all_sub_urls[url] = min(all_sub_urls.get(url, 99), src)

    _log(
        "INFO", f"  Direct keys: {len(new_key_source)} | Sub URLs: {len(all_sub_urls)}"
    )

    # --- Step 2: fetch all sub URLs in parallel ---
    if all_sub_urls:
        _log(
            "INFO",
            f"Step 2: fetching {len(all_sub_urls)} sub URLs ({SUB_WORKERS} workers)...",
        )
        t_subs = time.time()
        with ThreadPoolExecutor(max_workers=SUB_WORKERS) as ex:
            futures = {ex.submit(_fetch_and_extract, url): url for url in all_sub_urls}
            done = 0
            for fut in as_completed(futures):
                url = futures[fut]
                done += 1
                try:
                    keys, src = fut.result()
                    for k in keys:
                        new_key_source[k] = min(new_key_source.get(k, 99), src)
                    _log(
                        "INFO",
                        f"  [{done}/{len(all_sub_urls)}] +{len(keys)} keys src={src} <- {url[:55]}",
                    )
                except Exception as exc:
                    _log("WARN", f"  [{done}/{len(all_sub_urls)}] error: {exc}")
        _log("INFO", f"  Subs fetched in {time.time() - t_subs:.1f}s")

    # --- Step 3: merge with existing ---
    merged: dict[str, int] = dict(existing_key_source)
    for k, src in new_key_source.items():
        merged[k] = min(merged.get(k, 99), src)
    added = len(merged) - len(existing_key_source)
    _log("INFO", f"Step 3: merged. New: {added} | Total unique: {len(merged)}")

    # --- Step 4: TCP check ALL keys in parallel ---
    _log("INFO", "Step 4: TCP checking all keys...")
    all_keys_list = list(merged.keys())
    alive = tcp_check_all(all_keys_list)
    alive_count = sum(1 for v in alive.values() if v)
    _log("INFO", f"  Alive: {alive_count} | Dead: {len(all_keys_list) - alive_count}")

    # --- Step 5: save ---
    save_keys_sorted(merged, alive)

    # Update state
    if messages:
        state["last_message_id"] = max(m["id"] for m in messages)
        save_state(state)
        _log("INFO", f"State: last_message_id={state['last_message_id']}")

    elapsed_total = time.time() - t_start
    _log(
        "DONE",
        f"Alive: {alive_count} | Total: {len(merged)} | Time: {elapsed_total:.0f}s",
    )
    _log("DONE", f"Keys saved to {KEYS_FILE}")


if __name__ == "__main__":
    main()
