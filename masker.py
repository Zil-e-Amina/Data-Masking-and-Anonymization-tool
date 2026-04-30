import hashlib
import re

def mask_email(email):
    parts = email.split("@")
    name   = parts[0]
    domain = parts[1]
    masked_name = name[0] + "*" * (len(name) - 1)
    return f"{masked_name}@{domain}"

def mask_ip(ip):
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.x.x"

def mask_phone(phone):
    digits = re.sub(r"[^\d]", "", phone)
    return phone[:4] + "*" * (len(phone) - 6) + phone[-2:]

def mask_cnic(cnic):
    return cnic[:5] + "-*******-" + cnic[-1]

def mask_credit_card(cc):
    clean = re.sub(r"[-\s]", "", cc)
    return "**** **** **** " + clean[-4:]

def mask_name(name):
    parts = name.split()
    return parts[0][0] + "." + "*" * len(parts[0][1:]) + " " + parts[-1][0] + "." + "*" * len(parts[-1][1:])

def hash_value(val):
    return hashlib.sha256(val.encode()).hexdigest()[:12] + "..."

def mask_address(addr):
    parts = addr.split(",")
    parts[0] = "House ***"
    return ",".join(parts)

def mask_value(label, value):
    """Routes each detected label to correct masking function"""
    if label == "Email":
        return mask_email(value)
    elif label == "IP Address":
        return mask_ip(value)
    elif label == "Phone Number":
        return mask_phone(value)
    elif label == "CNIC":
        return mask_cnic(value)
    elif label == "Credit Card":
        return mask_credit_card(value)
    elif label == "Person Name":
        return mask_name(value)
    elif label == "IBAN":
        return hash_value(value)
    elif label == "MAC Address":
        return hash_value(value)
    elif label == "Home Address":
        return mask_address(value)
    else:
        return hash_value(value)