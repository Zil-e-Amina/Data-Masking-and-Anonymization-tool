from src.detector  import detect
from src.masker    import mask_value, reset_tokens
from src.anonymizer import validate_masking

TECHNIQUE_NAMES = {
    "Email":        "Partial Mask",
    "IP Address":   "Generalization",
    "Phone Number": "Partial Mask",
    "CNIC":         "Partial Mask",
    "Credit Card":  "Partial Mask",
    "Person Name":  "Substitution",
    "Home Address": "Partial Mask",
    "IBAN":         "Salted SHA-256",
    "MAC Address":  "Salted MD5",
    "Session Token":"Salted SHA-256",
    "Password":     "Suppression",
    "Username":     "Suppression",
    "Secret Key":   "Salted SHA-256",
    "URL":          "Encryption",
    "Date of Birth":"Suppression",
    "SHA256 Hash":  "Salted SHA-512",
}

RISK_SCORES = {
    "CRITICAL": 30,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":       5,
}

# Columns that are always sensitive regardless of their values
FORCE_MASK = {
    "person_name":      "Person Name",
    "analyst_assigned": "Person Name",
    "name":             "Person Name",
    "full_name":        "Person Name",
    "fullname":         "Person Name",
    "user_id":          "Username",
    "username":         "Username",
    "userid":           "Username",
    "user":             "Username",
    "phone_number":     "Phone Number",
    "phone":            "Phone Number",
    "mobile":           "Phone Number",
    "contact":          "Phone Number",
    "tel":              "Phone Number",
    "home_address":     "Home Address",
    "address":          "Home Address",
    "addr":             "Home Address",
    "residence":        "Home Address",
    "location":         "Home Address",
    "latitude":         "Geolocation",
    "longitude":        "Geolocation",
    "lat":              "Geolocation",
    "lon":              "Geolocation",
    "lng":              "Geolocation",
    "geolocation":      "Geolocation",
    "geo":              "Geolocation",
    "notes":            "Notes",
    "description":      "Notes",
    "note":             "Notes",
    "comments":         "Notes",
    "remark":           "Notes",
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
            "Technique": technique if technique != "auto"
                         else TECHNIQUE_NAMES.get(f["label"], "Hash"),
        })

    score      = sum(RISK_SCORES.get(f["risk_level"], 5) for f in findings)
    risk_score = min(score, 100)
    validation = validate_masking(text, masked_text, detect)

    return masked_text, results, risk_score, validation


def process_dataframe(df, technique="auto"):
    masked_df    = df.copy()
    col_report   = []
    total_masked = 0

    for col in df.columns:
        col_lower     = col.lower().strip()
        col_count     = 0
        col_status    = "✅ Safe"
        col_type      = "—"
        col_risk      = "—"
        forced_label  = FORCE_MASK.get(col_lower)

        for idx, val in df[col].items():
            cell   = str(val).strip()
            masked = None

            if forced_label:
                # Apply masking based on column name directly
                if forced_label == "Person Name":
                    masked = mask_value("Person Name", cell, technique)
                elif forced_label == "Username":
                    masked = mask_value("Session Token", cell, technique)
                elif forced_label == "Phone Number":
                    masked = mask_value("Phone Number", cell, technique)
                elif forced_label == "Home Address":
                    masked = mask_value("Home Address", cell, technique)
                elif forced_label == "Geolocation":
                    masked = "[GEO HIDDEN]"
                elif forced_label == "Notes":
                    # Scan notes text and mask any sensitive values inside
                    findings = detect(cell)
                    masked_cell = cell
                    for f in findings:
                        masked_cell = masked_cell.replace(
                            f["value"],
                            mask_value(f["label"], f["value"], technique)
                        )
                    masked = masked_cell

                if masked and masked != cell:
                    col_status = "🔴 Sensitive"
                    col_type   = forced_label
                    col_risk   = "MEDIUM"
                    col_count += 1
                    total_masked += 1
                    masked_df.at[idx, col] = masked

            else:
                # Auto detect sensitive values from cell content
                findings = detect(cell)
                if findings:
                    col_status = "🔴 Sensitive"
                    col_type   = findings[0]["label"]
                    col_risk   = findings[0]["risk_level"]
                    col_count += len(findings)
                    total_masked += len(findings)
                    masked_cell = cell
                    for f in findings:
                        masked_cell = masked_cell.replace(
                            f["value"],
                            mask_value(f["label"], f["value"], technique)
                        )
                    masked_df.at[idx, col] = masked_cell

        col_report.append({
            "Column":        col,
            "Status":        col_status,
            "Detected As":   col_type,
            "Risk Level":    col_risk,
            "Values Masked": col_count,
            "Technique":     technique if col_status != "✅ Safe" else "—",
        })

    return masked_df, col_report, total_masked