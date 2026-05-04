from src.detector   import detect
from src.masker     import mask_value, reset_tokens
from src.anonymizer import validate_masking

TECHNIQUE_NAMES = {
    "Email":         "Partial Mask",
    "IP Address":    "Generalization",
    "Phone Number":  "Partial Mask",
    "CNIC":          "Partial Mask",
    "Credit Card":   "Partial Mask",
    "Person Name":   "Substitution",
    "Home Address":  "Partial Mask",
    "Port Number":   "Selective Mask",
    "MAC Address":   "Salted MD5",
    "Hostname":      "Generalization",
    "CVE ID":        "Partial Mask",
    "JWT Token":     "Salted SHA-256",
    "User Agent":    "Generalization",
    "IBAN":          "Salted SHA-256",
    "Session Token": "Salted SHA-256",
    "Password":      "Suppression",
    "Username":      "Suppression",
    "Secret Key":    "Salted SHA-256",
    "Device ID":     "Salted SHA-256",
    "Process ID":    "Suppression",
    "URL":           "Encryption",
    "Date of Birth": "Suppression",
    "SHA256 Hash":   "Salted SHA-512",
    "MD5 Hash":      "Salted SHA-512",
    "Private Key":   "Suppression",
    "Passport":      "Suppression",
    "IMEI":          "Salted SHA-256",
}

RISK_SCORES = {
    "CRITICAL": 30,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":       5,
}

# Columns always treated as sensitive regardless of value
FORCE_MASK = {
    "person_name":      "Person Name",
    "name":             "Person Name",
    "full_name":        "Person Name",
    "fullname":         "Person Name",
    "analyst_assigned": "Person Name",
    "employee":         "Person Name",
    "customer":         "Person Name",
    "user_id":          "Username",
    "username":         "Username",
    "userid":           "Username",
    "login":            "Username",
    "account":          "Username",
    "phone_number":     "Phone Number",
    "phone":            "Phone Number",
    "mobile":           "Phone Number",
    "contact":          "Phone Number",
    "tel":              "Phone Number",
    "home_address":     "Home Address",
    "address":          "Home Address",
    "addr":             "Home Address",
    "residence":        "Home Address",
    "mac_address":      "MAC Address",
    "mac":              "MAC Address",
    "hwaddr":           "MAC Address",
    "src_port":         "Port Number",
    "dst_port":         "Port Number",
    "source_port":      "Port Number",
    "dest_port":        "Port Number",
    "port":             "Port Number",
    "latitude":         "Geolocation",
    "longitude":        "Geolocation",
    "lat":              "Geolocation",
    "lon":              "Geolocation",
    "lng":              "Geolocation",
    "geolocation":      "Geolocation",
    "geo":              "Geolocation",
    "location":         "Geolocation",
    "notes":            "Notes",
    "description":      "Notes",
    "note":             "Notes",
    "comments":         "Notes",
    "browser_agent":    "User Agent",
    "user_agent":       "User Agent",
    "agent":            "User Agent",
    "os_type":          "Device Info",
    "operating_system": "Device Info",
    "device_id":        "Device ID",
    "hostname":         "Hostname",
    "host":             "Hostname",
    "domain":           "Hostname",
    "isp_provider":     "ISP Info",
    "isp":              "ISP Info",
    "vpn_used":         "VPN Info",
    "cvss_score":       "Vulnerability",
    "vulnerability":    "Vulnerability",
    "cve":              "CVE ID",
    "jwt":              "JWT Token",
    "token":            "Session Token",
    "api_key":          "Secret Key",
    "secret":           "Secret Key",
    "private_key":      "Private Key",
    "passport":         "Passport",
    "imei":             "IMEI",
}

# Columns that must be converted to string before masking
NUMERIC_COLS = {
    "src_port", "dst_port", "port", "source_port", "dest_port",
    "latitude", "longitude", "lat", "lon", "lng",
    "packet_count", "bytes_sent", "bytes_received",
}


def process(text, technique="auto"):
    reset_tokens()
    findings    = detect(text)
    masked_text = text
    results     = []

    for f in findings:
        original    = f["value"]
        masked      = mask_value(f["label"], original, technique)
        masked_text = masked_text.replace(original, masked)
        results.append({
            "Risk":      f["icon"] + " " + f["risk_level"],
            "Type":      f["label"],
            "Original":  original,
            "Masked":    masked,
            "Technique": (technique if technique != "auto"
                          else TECHNIQUE_NAMES.get(f["label"], "Hash")),
        })

    score      = sum(RISK_SCORES.get(f["risk_level"], 5) for f in findings)
    risk_score = min(score, 100)
    validation = validate_masking(text, masked_text, detect)
    return masked_text, results, risk_score, validation


def _apply_forced(forced_label, cell, technique):
    """Apply masking based on column name"""
    special = {
        "Geolocation": "[GEO HIDDEN]",
        "Device Info": "[DEVICE HIDDEN]",
        "ISP Info":    "[ISP HIDDEN]",
        "VPN Info":    "[VPN HIDDEN]",
        "Vulnerability": "[VULN HIDDEN]",
    }

    if forced_label in special:
        return special[forced_label]

    if forced_label == "Notes":
        try:
            findings    = detect(cell)
            masked_cell = cell
            for f in findings:
                masked_cell = masked_cell.replace(
                    f["value"],
                    mask_value(f["label"], f["value"], technique)
                )
            return masked_cell
        except Exception:
            return cell

    label_map = {
        "Person Name":   "Person Name",
        "Username":      "Session Token",
        "Phone Number":  "Phone Number",
        "Home Address":  "Home Address",
        "MAC Address":   "MAC Address",
        "Port Number":   "Port Number",
        "User Agent":    "User Agent",
        "Device ID":     "Device ID",
        "Hostname":      "Hostname",
        "Session Token": "Session Token",
        "Secret Key":    "Secret Key",
        "JWT Token":     "JWT Token",
        "CVE ID":        "CVE ID",
        "Passport":      "Passport",
        "IMEI":          "IMEI",
        "Private Key":   "Private Key",
    }

    mask_label = label_map.get(forced_label)
    if mask_label:
        try:
            return mask_value(mask_label, cell, technique)
        except Exception:
            return cell

    return None


def process_dataframe(df, technique="auto"):
    import pandas as pd

    masked_df    = df.copy()
    col_report   = []
    total_masked = 0

    for col in df.columns:
        col_lower    = col.lower().strip()
        col_count    = 0
        col_status   = "✅ Safe"
        col_type     = "—"
        col_risk     = "—"
        forced_label = FORCE_MASK.get(col_lower)

        # Convert numeric columns to string first
        # so masked string values can be stored properly
        if col_lower in NUMERIC_COLS:
            masked_df[col] = masked_df[col].astype(str)

        for idx, val in df[col].items():
            try:
                cell = str(val).strip()

                if forced_label:
                    masked = _apply_forced(forced_label, cell, technique)
                    if masked is not None and masked != cell:
                        col_status    = "🔴 Sensitive"
                        col_type      = forced_label
                        col_risk      = "MEDIUM"
                        col_count    += 1
                        total_masked += 1
                        masked_df.at[idx, col] = masked
                else:
                    findings = detect(cell)
                    if findings:
                        col_status    = "🔴 Sensitive"
                        col_type      = findings[0]["label"]
                        col_risk      = findings[0]["risk_level"]
                        col_count    += len(findings)
                        total_masked += len(findings)
                        masked_cell   = cell
                        for f in findings:
                            masked_cell = masked_cell.replace(
                                f["value"],
                                mask_value(f["label"], f["value"], technique)
                            )
                        masked_df.at[idx, col] = masked_cell

            except Exception:
                continue

        col_report.append({
            "Column":        col,
            "Status":        col_status,
            "Detected As":   col_type,
            "Risk Level":    col_risk,
            "Values Masked": col_count,
            "Technique":     technique if col_status != "✅ Safe" else "—",
        })

    return masked_df, col_report, total_masked