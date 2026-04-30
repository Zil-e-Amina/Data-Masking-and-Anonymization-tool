from src.detector import detect
from src.masker  import mask_value

def process(text):
    """
    Takes raw input text.
    Returns:
      - masked_text   : text with all sensitive values replaced
      - findings      : list of what was found and how it was masked
      - risk_score    : 0-100 based on how much sensitive data found
    """
    findings = detect(text)
    masked_text = text

    results = []
    for f in findings:
        original = f["value"]
        masked   = mask_value(f["label"], original)
        # Replace in text
        masked_text = masked_text.replace(original, masked)
        results.append({
            "type":     f["label"],
            "original": original,
            "masked":   masked,
        })

    # Risk score — more sensitive fields = higher risk
    HIGH_RISK = {"Credit Card", "IBAN", "CNIC", "Session Token", "SHA256 Hash"}
    MED_RISK  = {"Email", "Phone Number", "IP Address", "MAC Address"}

    score = 0
    for r in results:
        if r["type"] in HIGH_RISK:
            score += 25
        elif r["type"] in MED_RISK:
            score += 15
        else:
            score += 10
    risk_score = min(score, 100)

    return masked_text, results, risk_score