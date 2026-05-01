import re

PATTERNS = {
    "IP Address":    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b",        "HIGH"),
    "Email":         (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "HIGH"),
    "Phone Number":  (r"(\+92|0)?[-.\s]?3[0-4]\d[-.\s]?\d{7}","HIGH"),
    "CNIC":          (r"\d{5}-\d{7}-\d{1}",                   "CRITICAL"),
    "Credit Card":   (r"\b(?:\d{4}[-\s]?){3}\d{4}\b",        "CRITICAL"),
    "IBAN":          (r"PK\d{2}[A-Z]{4}\d{16}",               "CRITICAL"),
    "MAC Address":   (r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", "MEDIUM"),
    "Person Name":   (r"\b([A-Z][a-z]+\s[A-Z][a-z]+)\b",     "MEDIUM"),
    "Home Address":  (r"\d+\s[\w\s]+,\s[\w\s]+,\s[\w\s]+",   "MEDIUM"),
    "Session Token": (r"\b[a-f0-9]{32}\b",                    "CRITICAL"),
    "SHA256 Hash":   (r"\b[a-f0-9]{64}\b",                    "HIGH"),
    "URL":           (r"https?://[^\s]+",                      "LOW"),
    "Date of Birth": (r"\b\d{2}[/-]\d{2}[/-]\d{4}\b",        "MEDIUM"),
    "Password":      (r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+","CRITICAL"),
    "Username":      (r"(?i)(username|user|login)\s*[:=]\s*\S+","MEDIUM"),
    "Secret Key":    (r"(?i)(secret|api_key|token|key)\s*[:=]\s*\S+","CRITICAL"),
}

RISK_COLORS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢"
}

def detect(text):
    findings = []
    seen = set()
    for label, (pattern, risk) in PATTERNS.items():
        for match in re.finditer(pattern, text):
            val = match.group()
            if val not in seen:
                seen.add(val)
                findings.append({
                    "label":      label,
                    "value":      val,
                    "risk_level": risk,
                    "icon":       RISK_COLORS[risk],
                    "start":      match.start(),
                    "end":        match.end()
                })
    return findings