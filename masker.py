import hashlib
import re
import base64
import random
import secrets

TOKEN_MAP     = {}
TOKEN_COUNTER = [1]


# ── Hashing ───────────────────────────────────────────────────────────────────
def hash_sha256(val):
    salt   = secrets.token_hex(8)
    hashed = hashlib.sha256(
        f"{salt}{val}".encode()
    ).hexdigest()[:16]
    return f"SHA256[{hashed}...]"


def hash_md5(val):
    salt   = secrets.token_hex(4)
    hashed = hashlib.md5(
        f"{salt}{val}".encode(),
        usedforsecurity=False
    ).hexdigest()[:12]
    return f"MD5[{hashed}...]"


def hash_sha512(val):
    salt   = secrets.token_hex(8)
    hashed = hashlib.sha512(
        f"{salt}{val}".encode()
    ).hexdigest()[:20]
    return f"SHA512[{hashed}...]"


# ── Encryption ────────────────────────────────────────────────────────────────
def encrypt_value(val):
    encoded = base64.b64encode(val.encode()).decode()
    return f"ENC[{encoded[:16]}...]"


# ── Tokenization ──────────────────────────────────────────────────────────────
def tokenize(val):
    if val not in TOKEN_MAP:
        TOKEN_MAP[val] = f"TOKEN_{TOKEN_COUNTER[0]:03d}"
        TOKEN_COUNTER[0] += 1
    return TOKEN_MAP[val]


def reset_tokens():
    TOKEN_MAP.clear()
    TOKEN_COUNTER[0] = 1


# ── Noise ─────────────────────────────────────────────────────────────────────
def add_noise(val):
    try:
        num   = float(re.sub(r"[^\d.]", "", str(val)))
        noise = num * random.uniform(0.05, 0.15)
        return str(round(num + noise, 2))
    except Exception:
        return hash_sha256(val)


# ── Email ─────────────────────────────────────────────────────────────────────
def mask_email(v):
    try:
        parts  = v.split("@")
        name   = parts[0]
        domain = parts[1] if len(parts) > 1 else "unknown"
        masked = name[0] + "*" * (len(name) - 1)
        return f"{masked}@{domain}"
    except Exception:
        return hash_sha256(v)


# ── IP Address ────────────────────────────────────────────────────────────────
def mask_ip(v):
    try:
        p = v.split(".")
        return f"{p[0]}.{p[1]}.x.x"
    except Exception:
        return "[IP HIDDEN]"


# ── Phone ─────────────────────────────────────────────────────────────────────
def mask_phone(v):
    try:
        v      = v.strip()
        digits = re.sub(r"[^\d]", "", v)
        if len(digits) < 6:
            return "[PHONE HIDDEN]"
        if v.startswith("+"):
            cc = digits[:2]
            return f"+{cc}-3**-****{digits[-2:]}"
        elif v.startswith("0"):
            return "0" + digits[1:4] + "*****" + digits[-2:]
        return digits[:3] + "*****" + digits[-2:]
    except Exception:
        return "[PHONE HIDDEN]"


# ── CNIC ──────────────────────────────────────────────────────────────────────
def mask_cnic(v):
    try:
        return v[:5] + "-*******-" + v[-1]
    except Exception:
        return "[CNIC HIDDEN]"


# ── Credit Card ───────────────────────────────────────────────────────────────
def mask_card(v):
    try:
        clean = re.sub(r"[-\s]", "", v)
        return "**** **** **** " + clean[-4:]
    except Exception:
        return "[CARD HIDDEN]"


# ── Person Name ───────────────────────────────────────────────────────────────
def mask_name(v):
    try:
        parts = v.strip().split()
        if len(parts) >= 2:
            return (
                parts[0][0] + "." + "*" * len(parts[0][1:])
                + " "
                + parts[-1][0] + "." + "*" * len(parts[-1][1:])
            )
        return parts[0][0] + "." + "*" * len(parts[0][1:])
    except Exception:
        return "[NAME HIDDEN]"


# ── Home Address ──────────────────────────────────────────────────────────────
def mask_address(v):
    try:
        parts    = v.split(",")
        parts[0] = "House ***"
        return ",".join(parts)
    except Exception:
        return "[ADDRESS HIDDEN]"


# ── Password ──────────────────────────────────────────────────────────────────
def mask_password(v):
    try:
        if ":" in v:
            return v.split(":")[0].strip() + ": [HIDDEN]"
        elif "=" in v:
            return v.split("=")[0].strip() + "= [HIDDEN]"
        return "[HIDDEN]"
    except Exception:
        return "[HIDDEN]"


# ── MAC Address ───────────────────────────────────────────────────────────────
def mask_mac(v):
    """
    Hash any MAC format:
    00:1A:2B:3C:4D:5E  full colon
    00:1A:2B:3C:4D     partial colon
    00-1A-2B-3C-4D-5E  dash
    001A.2B3C.4D5E     Cisco dot
    001A2B3C4D5E       no separator
    """
    return hash_md5(v)


# ── Port Number ───────────────────────────────────────────────────────────────
def mask_port(v):
    """
    Mask port numbers:
    Known sensitive ports show service name
    Ephemeral ports above 1024 show range
    """
    try:
        port = int(re.sub(r"[^\d]", "", str(v)))
        sensitive = {
            20:    "FTP-Data",
            21:    "FTP",
            22:    "SSH",
            23:    "Telnet",
            25:    "SMTP",
            53:    "DNS",
            80:    "HTTP",
            110:   "POP3",
            143:   "IMAP",
            443:   "HTTPS",
            445:   "SMB",
            1433:  "MSSQL",
            1521:  "Oracle",
            3306:  "MySQL",
            3389:  "RDP",
            5432:  "PostgreSQL",
            5900:  "VNC",
            6379:  "Redis",
            8080:  "HTTP-Alt",
            8443:  "HTTPS-Alt",
            27017: "MongoDB",
        }
        if port in sensitive:
            return f"[PORT/{sensitive[port]}/MASKED]"
        if port > 1024:
            return "[EPHEMERAL/MASKED]"
        return f"[PORT/{port}/MASKED]"
    except Exception:
        return "[PORT/MASKED]"


# ── Hostname ──────────────────────────────────────────────────────────────────
def mask_hostname(v):
    try:
        parts = v.split(".")
        if len(parts) >= 2:
            return "***." + parts[-1]
        return hash_sha256(v)
    except Exception:
        return "[HOST HIDDEN]"


# ── CVE ID ────────────────────────────────────────────────────────────────────
def mask_cve(v):
    try:
        parts = v.split("-")
        return f"CVE-{parts[1]}-****"
    except Exception:
        return "[CVE HIDDEN]"


# ── JWT Token ─────────────────────────────────────────────────────────────────
def mask_jwt(v):
    return hash_sha256(v)


# ── User Agent ────────────────────────────────────────────────────────────────
def mask_user_agent(v):
    browsers = [
        "Chrome", "Firefox", "Safari", "Edge",
        "Opera", "curl", "wget", "python", "Go-http"
    ]
    try:
        for b in browsers:
            if b.lower() in v.lower():
                return f"[{b}/HIDDEN]"
        return "[AGENT HIDDEN]"
    except Exception:
        return "[AGENT HIDDEN]"


# ── Main router ────────────────────────────────────────────────────────────────
def mask_value(label, value, technique="auto"):
    # User selected technique
    if technique == "hash":     return hash_sha256(value)
    if technique == "encrypt":  return encrypt_value(value)
    if technique == "tokenize": return tokenize(value)
    if technique == "suppress": return "[SUPPRESSED]"
    if technique == "noise":    return add_noise(value)

    # Auto mode — best per type
    dispatch = {
        "Email":         mask_email,
        "IP Address":    mask_ip,
        "Phone Number":  mask_phone,
        "CNIC":          mask_cnic,
        "Credit Card":   mask_card,
        "Person Name":   mask_name,
        "Home Address":  mask_address,
        "Password":      mask_password,
        "Username":      mask_password,
        "Port Number":   mask_port,
        "MAC Address":   mask_mac,
        "Hostname":      mask_hostname,
        "CVE ID":        mask_cve,
        "JWT Token":     mask_jwt,
        "User Agent":    mask_user_agent,
        "Device ID":     hash_sha256,
        "Process ID":    lambda v: "[PID HIDDEN]",
        "IBAN":          hash_sha256,
        "Session Token": hash_sha256,
        "SHA256 Hash":   hash_sha512,
        "MD5 Hash":      hash_sha512,
        "Secret Key":    hash_sha256,
        "URL":           encrypt_value,
        "Date of Birth": lambda v: "[DOB HIDDEN]",
        "Private Key":   lambda v: "[PRIVATE KEY REMOVED]",
        "Passport":      lambda v: "[PASSPORT HIDDEN]",
        "IMEI":          hash_sha256,
    }
    fn = dispatch.get(label, hash_sha256)
    return fn(value)