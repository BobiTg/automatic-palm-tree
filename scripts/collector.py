import base64
import json
import os
import re
import sys
import time
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


def fetch_page(url: str) -> str | None:
    """Fetch a URL with browser headers; retry up to 3 times on failure."""
    headers = {
        "User-Agent": BROWSER_UA,
        "Accept-Language": "ru-RU,ru;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    for attempt in range(1, 4):
        try:
            resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
            if resp.status_code == 200:
                return resp.text
            print(
                f"[WARN] fetch_page {url} → HTTP {resp.status_code} (attempt {attempt})"
            )
        except Exception as exc:
            print(f"[WARN] fetch_page {url} attempt {attempt} error: {exc}")
        if attempt < 3:
            time.sleep(2)
    return None


def fetch_subscription(url: str) -> str | None:
    """Try each User-Agent until we get a valid subscription response."""
    for ua in USER_AGENTS:
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": ua},
                timeout=20,
                allow_redirects=True,
            )
            if resp.status_code == 200 and len(resp.text) > 30:
                return resp.text
        except Exception as exc:
            print(f"[WARN] fetch_subscription {url} ua={ua!r}: {exc}")
    return None


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

    while not stop:
        url = (
            CHANNEL_URL
            if next_before is None
            else f"{CHANNEL_URL}?before={next_before}"
        )
        print(f"[INFO] Fetching {url}")
        html = fetch_page(url)
        if not html:
            print("[WARN] Empty page response, stopping.")
            break

        page_messages = parse_channel_page(html)
        if not page_messages:
            print("[INFO] No messages on page, stopping.")
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

        if new_on_page == 0:
            break

        # Prepare next page (paginate backwards)
        min_id = min(m["id"] for m in page_messages)
        if next_before is not None and min_id >= next_before:
            # No progress
            break
        next_before = min_id

        if not stop:
            time.sleep(1.5)

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


def process_message(msg: dict) -> set:
    """Process one message; return set of VPN keys found."""
    found_keys: set[str] = set()

    # 1. Direct keys in message text
    direct = extract_keys(msg["text"])
    if direct:
        print(f"  [MSG {msg['id']}] Direct keys: {len(direct)}")
    found_keys.update(direct)

    # 2. Subscription URLs
    sub_urls = extract_subscription_urls(msg["text"], msg["links"])
    for url in sub_urls:
        try:
            print(f"  [MSG {msg['id']}] Fetching sub: {url}")
            raw = fetch_subscription(url)
            if raw:
                decoded = decode_content(raw)
                keys = extract_keys(decoded)
                print(f"    → {len(keys)} keys found")
                found_keys.update(keys)
            else:
                print(f"    → no response")
        except Exception as exc:
            print(f"  [WARN] Error processing sub URL {url}: {exc}")

    return found_keys


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "update"
    print(f"[INFO] Mode: {mode}")

    os.makedirs("keys", exist_ok=True)

    state = load_state()
    existing_keys = load_existing_keys()
    print(f"[INFO] Existing keys loaded: {len(existing_keys)}")

    if mode == "init":
        messages = collect_messages(since_days=DAYS_INIT)
    else:
        last_id = state.get("last_message_id", 0)
        print(f"[INFO] Collecting messages after id={last_id}")
        messages = collect_messages(after_id=last_id)

    print(f"[INFO] Processing {len(messages)} messages")

    new_keys: set[str] = set()
    for msg in messages:
        try:
            keys = process_message(msg)
            new_keys.update(keys)
        except Exception as exc:
            print(f"[WARN] Error processing message {msg.get('id')}: {exc}")

    # Update state with latest seen message id
    if messages:
        state["last_message_id"] = max(m["id"] for m in messages)
        save_state(state)
        print(f"[INFO] State updated: last_message_id={state['last_message_id']}")

    # Merge and deduplicate
    all_keys = existing_keys | new_keys
    added = len(all_keys) - len(existing_keys)
    print(f"[DONE] New keys: {added}, Total: {len(all_keys)}")

    save_keys(all_keys)
    print(f"[DONE] Keys saved to {KEYS_FILE}")


if __name__ == "__main__":
    main()
