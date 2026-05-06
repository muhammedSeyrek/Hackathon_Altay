"""
Esnek log parser.
Yaygın .log formatlarını otomatik algılar:
- SSH / auth.log (Failed password, Invalid user)
- Apache/Nginx access log (4xx/5xx, suspicious requests)
- Syslog
- Generic timestamp + mesaj
"""

import re
from collections import Counter
from datetime import datetime
import pandas as pd

# --- Saldırı/şüpheli olay kalıpları ---
ATTACK_PATTERNS = [
    # SSH brute force
    (re.compile(r"Failed password", re.I), "ssh_failed_password"),
    (re.compile(r"Invalid user", re.I), "ssh_invalid_user"),
    (re.compile(r"authentication failure", re.I), "auth_failure"),
    (re.compile(r"Connection closed by .* \[preauth\]", re.I), "ssh_preauth_disconnect"),
    (re.compile(r"PAM .* check pass; user unknown", re.I), "pam_unknown_user"),

    # Web saldırıları
    (re.compile(r"\b(union|select|insert|drop|--|/\*|0x[0-9a-f]+)\b.*(\?|=)", re.I), "sql_injection"),
    (re.compile(r"<script|javascript:|onerror=|onload=", re.I), "xss_attempt"),
    (re.compile(r"\.\./|\.\.\\|/etc/passwd|/proc/self", re.I), "path_traversal"),
    (re.compile(r"(wp-admin|wp-login|phpmyadmin|\.env|\.git/)", re.I), "scanner_recon"),

    # HTTP hata kodları (4xx/5xx)
    (re.compile(r'"\s+(40[01345]|429)\s+'), "http_4xx"),
    (re.compile(r'"\s+5\d\d\s+'), "http_5xx"),

    # Genel
    (re.compile(r"\b(error|denied|blocked|attack|exploit|malware)\b", re.I), "generic_alert"),
    (re.compile(r"\bbrute[\s-]?force\b", re.I), "brute_force"),
    (re.compile(r"port\s*scan", re.I), "port_scan"),
]

# --- Timestamp formatları ---
# Yaygın log timestamp'leri
TIMESTAMP_PATTERNS = [
    # 2024-01-15 14:32:01  veya 2024-01-15T14:32:01
    (re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}):(\d{2}):(\d{2})"), "iso"),
    # Jan 15 14:32:01  (syslog)
    (re.compile(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})"), "syslog"),
    # [15/Jan/2024:14:32:01 +0000]  (Apache/Nginx)
    (re.compile(r"\[(\d{1,2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})"), "apache"),
    # 15-01-2024 14:32:01
    (re.compile(r"(\d{2})-(\d{2})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})"), "dmy"),
]

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_hour(line: str):
    """Bir log satırından saat (0-23) çıkarmaya çalışır."""
    for pattern, ptype in TIMESTAMP_PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        try:
            if ptype == "iso":
                return int(m.group(2))
            elif ptype == "syslog":
                return int(m.group(3))
            elif ptype == "apache":
                return int(m.group(4))
            elif ptype == "dmy":
                return int(m.group(4))
        except (ValueError, IndexError):
            continue
    return None


def classify_line(line: str):
    """Satırın hangi saldırı kategorisine girdiğini döner. Yoksa None."""
    for pattern, category in ATTACK_PATTERNS:
        if pattern.search(line):
            return category
    return None


def extract_ip(line: str):
    m = IP_PATTERN.search(line)
    return m.group(0) if m else None


def parse_log_text(text: str) -> pd.DataFrame:
    """
    Log metnini DataFrame'e çevirir.
    Sütunlar: line, hour, category, ip, is_attack
    """
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        hour = extract_hour(line)
        category = classify_line(line)
        ip = extract_ip(line)

        rows.append({
            "line": line[:300],  # çok uzun satırları kırp
            "hour": hour,
            "category": category,
            "ip": ip,
            "is_attack": category is not None,
        })

    return pd.DataFrame(rows)


def summarize_attacks(df: pd.DataFrame) -> dict:
    """Analiz özeti döner."""
    if df.empty:
        return {
            "total": 0,
            "attack_count": 0,
            "hourly": pd.Series([0] * 24, index=range(24)),
            "peak_hour": 0,
            "peak_hour_count": 0,
            "top_categories": {},
            "top_ips": {},
        }

    attacks = df[df["is_attack"]]

    # Saatlik dağılım (sadece saldırılar için)
    hourly = pd.Series([0] * 24, index=range(24))
    if not attacks.empty:
        valid = attacks.dropna(subset=["hour"])
        if not valid.empty:
            counts = valid["hour"].astype(int).value_counts()
            for h, c in counts.items():
                if 0 <= h <= 23:
                    hourly[h] = c

    peak_hour = int(hourly.idxmax()) if hourly.max() > 0 else 0
    peak_hour_count = int(hourly.max())

    # En çok görülen kategoriler
    top_cats = {}
    if not attacks.empty:
        top_cats = dict(Counter(attacks["category"].dropna()).most_common(10))

    # En çok saldıran IP'ler
    top_ips = {}
    if not attacks.empty:
        top_ips = dict(Counter(attacks["ip"].dropna()).most_common(10))

    return {
        "total": len(df),
        "attack_count": int(attacks.shape[0]),
        "hourly": hourly,
        "peak_hour": peak_hour,
        "peak_hour_count": peak_hour_count,
        "top_categories": top_cats,
        "top_ips": top_ips,
    }


if __name__ == "__main__":
    # Hızlı test
    sample = """Jan 15 03:14:22 server sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2
Jan 15 03:14:25 server sshd[1235]: Failed password for admin from 192.168.1.50 port 22 ssh2
Jan 15 03:15:01 server sshd[1236]: Invalid user oracle from 10.0.0.5
2024-01-15 14:32:01 192.168.1.100 GET /wp-admin/ 404
192.168.1.200 - - [15/Jan/2024:09:23:11 +0000] "GET /admin?id=1' OR '1'='1 HTTP/1.1" 403 0
"""
    df = parse_log_text(sample)
    print(df)
    print("\nÖzet:")
    print(summarize_attacks(df))
