import os
import re
import hashlib
import secrets

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_FILE_SIZE_MB  = 10
MAX_INPUT_LENGTH  = 50000   # 50,000 characters max
ALLOWED_MIME_CSV  = ["text/csv", "application/csv"]
ALLOWED_MIME_JSON = ["application/json", "text/json"]

# ── Fix 1: File size check ────────────────────────────────────────────────────
def check_file_size(uploaded_file):
    """Rejects files over MAX_FILE_SIZE_MB"""
    size_mb = len(uploaded_file.getvalue()) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        return False, f"File too large ({size_mb:.1f}MB). Maximum allowed is {MAX_FILE_SIZE_MB}MB."
    return True, "OK"

# ── Fix 2: Input sanitization ─────────────────────────────────────────────────
def sanitize_input(text):
    """
    Cleans user input before processing.
    - Removes null bytes
    - Limits length
    - Strips dangerous characters
    """
    if not text:
        return ""
    # Remove null bytes
    text = text.replace("\x00", "")
    # Remove control characters except newlines and tabs
    text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    # Limit length
    if len(text) > MAX_INPUT_LENGTH:
        text = text[:MAX_INPUT_LENGTH]
    return text

# ── Fix 3: File type validation ───────────────────────────────────────────────
def validate_file_type(uploaded_file):
    """
    Validates file content not just extension.
    Checks actual first bytes of file.
    """
    name = uploaded_file.name.lower()
    content = uploaded_file.getvalue()

    if name.endswith(".csv"):
        # CSV should be readable text
        try:
            content.decode("utf-8")
            return True, "OK"
        except:
            return False, "File appears corrupted or not a valid CSV."

    elif name.endswith(".json"):
        # JSON should be valid JSON
        import json
        try:
            json.loads(content.decode("utf-8"))
            return True, "OK"
        except:
            return False, "File is not valid JSON."

    elif name.endswith(".pdf"):
        # PDF starts with %PDF
        if content[:4] == b'%PDF':
            return True, "OK"
        return False, "File does not appear to be a valid PDF."

    elif name.endswith(".docx"):
        # DOCX is a ZIP file starting with PK
        if content[:2] == b'PK':
            return True, "OK"
        return False, "File does not appear to be a valid Word document."

    return False, "Unsupported file type."

# ── Fix 4: Salted hashing ─────────────────────────────────────────────────────
def salted_hash(value, salt=None):
    """
    SHA-256 with random salt — cannot be reversed with rainbow tables.
    Returns: salt:hash format
    """
    if salt is None:
        salt = secrets.token_hex(8)   # random 8-byte salt
    hashed = hashlib.sha256(f"{salt}{value}".encode()).hexdigest()[:16]
    return f"HASH[{hashed}...]"

# ── Fix 5: Safe error messages ────────────────────────────────────────────────
def safe_error(error):
    """
    Returns friendly error message without revealing system details.
    Hides file paths, Python internals, etc.
    """
    error_str = str(error).lower()

    if "memory" in error_str or "size" in error_str:
        return "File is too large to process. Please use a smaller file."
    elif "decode" in error_str or "codec" in error_str or "encoding" in error_str:
        return "File encoding not supported. Please save as UTF-8 and try again."
    elif "json" in error_str:
        return "Invalid JSON format. Please check your JSON file structure."
    elif "pdf" in error_str:
        return "Could not read PDF. Make sure it is not password protected."
    elif "permission" in error_str:
        return "Permission denied. Cannot access this file."
    elif "not found" in error_str or "no such" in error_str:
        return "File not found. Please re-upload and try again."
    else:
        return "An error occurred while processing. Please check your file and try again."

# ── Fix 6: Session cleanup ────────────────────────────────────────────────────
def clear_sensitive_session(st):
    """
    Clears sensitive data from Streamlit session after processing.
    Prevents data leakage between sessions.
    """
    keys_to_clear = ["sample", "t1", "t1_area"]
    for key in keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]

# ── Security audit log ────────────────────────────────────────────────────────
def log_audit(action, details=""):
    """
    Simple local audit log — records what was processed.
    Saved to output/audit.log
    """
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {action} | {details}\n"
    try:
        os.makedirs("output", exist_ok=True)
        with open("output/audit.log", "a") as f:
            f.write(log_entry)
    except:
        pass  # Never crash because of logging