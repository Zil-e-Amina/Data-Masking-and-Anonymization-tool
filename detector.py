import re

# All patterns to detect sensitive data
PATTERNS = {
    "IP Address":      r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "Email":           r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Phone Number":    r"(\+92|0)?[-.\s]?3[0-4]\d[-.\s]?\d{7}",
    "CNIC":            r"\d{5}-\d{7}-\d{1}",
    "Credit Card":     r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "IBAN":            r"PK\d{2}[A-Z]{4}\d{16}",
    "MAC Address":     r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}",
    "Person Name":     r"\b([A-Z][a-z]+\s[A-Z][a-z]+)\b",
    "Home Address":    r"\d+\s[\w\s]+,\s[\w\s]+,\s[\w\s]+",
    "Session Token":   r"\b[a-f0-9]{32}\b",
    "SHA256 Hash":     r"\b[a-f0-9]{64}\b",
    "URL":             r"https?://[^\s]+",
    "Date of Birth":   r"\b\d{2}[/-]\d{2}[/-]\d{4}\b",
}

def detect(text):
    """
    Scans input text and returns list of findings.
    Each finding: { label, matched_value, start, end }
    """
    findings = []
    for label, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text):
            findings.append({
                "label":   label,
                "value":   match.group(),
                "start":   match.start(),
                "end":     match.end()
            })
    # Remove duplicates (same value detected by multiple patterns)
    seen = set()
    unique = []
    for f in findings:
        if f["value"] not in seen:
            seen.add(f["value"])
            unique.append(f)
    return unique