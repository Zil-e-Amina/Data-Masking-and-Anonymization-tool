import hashlib, re, base64, random, secrets

TOKEN_MAP     = {}
TOKEN_COUNTER = [1]

# ── Hashing with salt ─────────────────────────────────────────────────────────
def hash_sha256(val):
    salt   = secrets.token_hex(8)
    hashed = hashlib.sha256(f"{salt}{val}".encode()).hexdigest()[:16]
    return f"SHA256[{hashed}...]"

def hash_md5(val):
    salt   = secrets.token_hex(4)
    hashed = hashlib.md5(f"{salt}{val}".encode(), usedforsecurity=False).hexdigest()[:12]
    return f"MD5[{hashed}...]"

def hash_sha512(val):
    salt   = secrets.token_hex(8)
    hashed = hashlib.sha512(f"{salt}{val}".encode()).hexdigest()[:20]
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
        num   = float(re.sub(r"[^\d.]", "", val))
        noise = num * random.uniform(0.05, 0.15)
        return str(round(num + noise, 2))
    except:
        return hash_sha256(val)

# ── Specific masking functions ────────────────────────────────────────────────
def mask_email(v):
    p = v.split("@")
    return p[0][0] + "*" * (len(p[0])-1) + "@" + p[1]

def mask_ip(v):
    p = v.split(".")
    return f"{p[0]}.{p[1]}.x.x"

def mask_phone(v):
    return v[:4] + "*" * (len(v)-6) + v[-2:]

def mask_cnic(v):
    return v[:5] + "-*******-" + v[-1]

def mask_card(v):
    c = re.sub(r"[-\s]", "", v)
    return "**** **** **** " + c[-4:]

def mask_name(v):
    p = v.split()
    return p[0][0] + "."+"*"*len(p[0][1:])+" "+p[-1][0]+"."+"*"*len(p[-1][1:])

def mask_address(v):
    p    = v.split(",")
    p[0] = "House ***"
    return ",".join(p)

def mask_password(v):
    label = v.split(":")[0] if ":" in v else v.split("=")[0]
    return label.strip() + ": [HIDDEN]"

# ── Main router ───────────────────────────────────────────────────────────────
def mask_value(label, value, technique="auto"):
    if technique == "hash":     return hash_sha256(value)
    if technique == "encrypt":  return encrypt_value(value)
    if technique == "tokenize": return tokenize(value)
    if technique == "suppress": return "[SUPPRESSED]"
    if technique == "noise":    return add_noise(value)

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
        "IBAN":          hash_sha256,
        "MAC Address":   hash_md5,
        "Session Token": hash_sha256,
        "SHA256 Hash":   hash_sha512,
        "Secret Key":    hash_sha256,
        "URL":           encrypt_value,
        "Date of Birth": lambda v: "[DOB HIDDEN]",
    }
    return dispatch.get(label, hash_sha256)(value)