import pandas as pd
import random

def shuffle_column(df, col):
    df[col] = df[col].sample(frac=1).reset_index(drop=True)
    return df

def k_anonymity(df, col, k=3):
    counts = df[col].value_counts()
    rare   = counts[counts < k].index
    df[col] = df[col].apply(lambda x: "OTHER" if x in rare else x)
    return df

def generalize_numeric(df, col, bins=5):
    try:    df[col] = pd.cut(df[col], bins=bins).astype(str)
    except: pass
    return df

def validate_masking(original_text, masked_text, detect_fn):
    original  = detect_fn(original_text)
    remaining = detect_fn(masked_text)
    return {
        "original_count":  len(original),
        "remaining_count": len(remaining),
        "still_exposed":   remaining,
        "safe_to_share":   len(remaining) == 0
    }