import re

# ── Standalone patterns ────────────────────────────────────────────────────────
STANDALONE = {
    "Email": (
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "HIGH"
    ),
    "IP Address": (
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "HIGH"
    ),
    "Phone Number": (
        r"\b0[3][0-9]{2}[-\s]?[0-9]{7}\b"
        r"|\+[0-9]{1,3}[-\s]?[0-9]{8,12}\b"
        r"|\b[0-9]{3}[-\s][0-9]{3}[-\s][0-9]{4}\b",
        "HIGH"
    ),
    "CNIC": (
        r"\b\d{5}-\d{7}-\d{1}\b",
        "CRITICAL"
    ),
    "Credit Card": (
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "CRITICAL"
    ),
    "IBAN": (
        r"\bPK\d{2}[A-Z]{4}\d{16}\b",
        "CRITICAL"
    ),
    "MAC Address": (
        r"\b[0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){2,5}\b"
        r"|\b[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\b"
        r"|\b[0-9a-fA-F]{12}\b",
        "MEDIUM"
    ),
    "Session Token": (
        r"\b[a-f0-9]{32}\b",
        "CRITICAL"
    ),
    "SHA256 Hash": (
        r"\b[a-f0-9]{64}\b",
        "HIGH"
    ),
    "MD5 Hash": (
        r"\b[a-f0-9]{32}\b",
        "HIGH"
    ),
    "JWT Token": (
        r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b",
        "CRITICAL"
    ),
    "CVE ID": (
        r"\bCVE-\d{4}-\d{4,7}\b",
        "HIGH"
    ),
    "URL": (
        r"https?://[^\s]+",
        "LOW"
    ),
    "Date of Birth": (
        r"\b\d{2}[/-]\d{2}[/-]\d{4}\b",
        "MEDIUM"
    ),
    "Private Key": (
        r"-----BEGIN [A-Z ]+ KEY-----",
        "CRITICAL"
    ),
    "Passport": (
        r"\b[A-Z]{2}[0-9]{7}\b",
        "CRITICAL"
    ),
    "IMEI": (
        r"\b\d{15}\b",
        "HIGH"
    ),
    "Hostname": (
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|edu|gov|pk|io|co)\b",
        "MEDIUM"
    ),
}

# ── Label-based patterns ───────────────────────────────────────────────────────
LABELED = {
    "Person Name": (
        r"(?i)(name|fullname|full_name|person|employee|customer)"
        r"\s*[:=]\s*([^\n,]{2,50})",
        "MEDIUM"
    ),
    "Password": (
        r"(?i)(password|passwd|pwd|pass)\s*[:=]\s*([^\s\n]{3,})",
        "CRITICAL"
    ),
    "Secret Key": (
        r"(?i)(secret|api_key|apikey|token|key|auth|access_token)"
        r"\s*[:=]\s*([^\s\n]{4,})",
        "CRITICAL"
    ),
    "Home Address": (
        r"(?i)(address|addr|location|residence)\s*[:=]\s*([^\n]{5,})",
        "MEDIUM"
    ),
    "Username": (
        r"(?i)(username|login|account|user_id)\s*[:=]\s*([^\s\n]{2,})",
        "MEDIUM"
    ),
    "Port Number": (
        r"(?i)(port|src_port|dst_port|dport|sport)\s*[:=]\s*(\d{1,5})",
        "MEDIUM"
    ),
    "Device ID": (
        r"(?i)(device_id|device|imei|serial|hardware_id)"
        r"\s*[:=]\s*([^\s\n]{4,})",
        "HIGH"
    ),
    "User Agent": (
        r"(?i)(user.agent|browser|agent)\s*[:=]\s*([^\n]{4,})",
        "LOW"
    ),
    "Process ID": (
        r"(?i)(pid|process_id|proc)\s*[:=]\s*(\d+)",
        "LOW"
    ),
}

# ── Log file patterns ──────────────────────────────────────────────────────────
LOG_PATTERNS = {
    "IP Address": (
        r"(?:src_ip|dst_ip|source_ip|dest_ip|ip|host|"
        r"remote_addr|client_ip|server_ip)\s*[=:]\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3})",
        "HIGH"
    ),
    "Email": (
        r"(?:user|email|mail|from|to|sender|recipient)\s*[=:]\s*"
        r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "HIGH"
    ),
    "Phone Number": (
        r"(?:phone|mobile|tel|contact)\s*[=:]\s*"
        r"(0[3][0-9]{9}|\+[0-9]{1,3}[0-9]{8,12})",
        "HIGH"
    ),
    "MAC Address": (
        r"(?:mac|mac_addr|hwaddr|ether)\s*[=:]\s*"
        r"([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){2,5}"
        r"|[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
        r"|[0-9a-fA-F]{12})",
        "MEDIUM"
    ),
    "Port Number": (
        r"(?:port|src_port|dst_port|dport|sport)\s*[=:]\s*(\d{1,5})",
        "MEDIUM"
    ),
    "Username": (
        r"(?:username|user|name|employee|operator|login)\s*[=:]\s*"
        r"([a-zA-Z][a-zA-Z0-9._-]{1,})",
        "MEDIUM"
    ),
    "Password": (
        r"(?:password|passwd|pwd|pass)\s*[=:]\s*([^\s\n]{3,})",
        "CRITICAL"
    ),
    "Secret Key": (
        r"(?:api_key|apikey|secret|token|auth_token|access_token)"
        r"\s*[=:]\s*([^\s\n]{4,})",
        "CRITICAL"
    ),
    "CVE ID": (
        r"CVE-\d{4}-\d{4,7}",
        "HIGH"
    ),
    "JWT Token": (
        r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "CRITICAL"
    ),
    "Hostname": (
        r"(?:host|hostname|server|domain)\s*[=:]\s*"
        r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "MEDIUM"
    ),
    "Device ID": (
        r"(?:device_id|device|imei|serial)\s*[=:]\s*([^\s\n]{4,})",
        "HIGH"
    ),
    "User Agent": (
        r"(?:user.agent|browser|agent)\s*[=:]\s*([^\n]{4,})",
        "LOW"
    ),
    "Process ID": (
        r"(?:pid|process_id)\s*[=:]\s*(\d+)",
        "LOW"
    ),
}

ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢"
}


def is_log_format(text):
    indicators = [
        r"\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}",
        r"\b(ERROR|WARN|WARNING|INFO|DEBUG|CRITICAL|ALERT|FATAL)\b",
        r"\w+[=:]\w+",
        r"\[\d+\]",
        r"\b(GET|POST|PUT|DELETE|HTTP)\b",
    ]
    return sum(1 for p in indicators if re.search(p, text)) >= 2


def extract_value(match):
    try:
        if match.lastindex and match.lastindex >= 2:
            val = match.group(2)
            if val and val.strip():
                return val.strip()
        if match.lastindex and match.lastindex >= 1:
            val = match.group(1)
            if val and val.strip():
                return val.strip()
    except Exception:
        pass
    full = match.group()
    if ":" in full:
        return full.split(":", 1)[1].strip()
    if "=" in full:
        return full.split("=", 1)[1].strip()
    return full.strip()


def detect(text):
    findings = []
    seen     = set()

    if is_log_format(text):
        pattern_sets = [LOG_PATTERNS, STANDALONE]
    else:
        pattern_sets = [LABELED, STANDALONE]

    for pattern_set in pattern_sets:
        for label, (pattern, risk) in pattern_set.items():
            for match in re.finditer(pattern, text):
                val = extract_value(match)
                val = val.strip().strip('"').strip("'")
                if not val or len(val) < 2:
                    continue
                if val in seen:
                    continue
                seen.add(val)
                findings.append({
                    "label":      label,
                    "value":      val,
                    "risk_level": risk,
                    "icon":       ICONS[risk],
                    "start":      match.start(),
                    "end":        match.end()
                })

    return findings