import pandas as pd
import random


def shuffle_column(df, col):
    """Randomly reorder values in a column"""
    df[col] = df[col].sample(frac=1).reset_index(drop=True)
    return df


def k_anonymity(df, col, k=3):
    """Group rare values into OTHER"""
    counts = df[col].value_counts()
    rare   = counts[counts < k].index
    df[col] = df[col].apply(lambda x: "OTHER" if x in rare else x)
    return df


def generalize_numeric(df, col, bins=5):
    """Turn exact numbers into ranges"""
    try:
        df[col] = pd.cut(df[col], bins=bins).astype(str)
    except Exception:
        pass
    return df


def validate_masking(original_text, masked_text, detect_fn):
    """Rescan masked output to confirm no sensitive data remains"""
    original  = detect_fn(original_text)
    remaining = detect_fn(masked_text)
    return {
        "original_count":  len(original),
        "remaining_count": len(remaining),
        "still_exposed":   remaining,
        "safe_to_share":   len(remaining) == 0
    }