"""Input validation and error handling for DES cryptographic requests."""

import re
from typing import Tuple, Optional


class ValidationError(Exception):
    """Custom exception raised for invalid user input."""
    def __init__(self, message: str, field: str = "general"):
        super().__init__(message)
        self.message = message
        self.field = field


def validate_hex_string(val: str, expected_length: Optional[int] = None, field_name: str = "Input") -> str:
    """Validate that input string is a valid hexadecimal representation."""
    cleaned = val.strip().replace(" ", "").replace("0x", "").replace("0X", "")
    if not cleaned:
        raise ValidationError(f"{field_name} cannot be empty.", field=field_name)
    
    if not re.fullmatch(r"^[0-9a-fA-F]+$", cleaned):
        raise ValidationError(f"{field_name} must contain only hexadecimal digits (0-9, A-F).", field=field_name)
    
    if expected_length is not None and len(cleaned) != expected_length:
        raise ValidationError(
            f"{field_name} must be exactly {expected_length} hexadecimal characters "
            f"({expected_length * 4} bits). Received {len(cleaned)} characters.",
            field=field_name
        )
    return cleaned.upper()


def normalize_plain_text_key(key_input: str) -> Tuple[str, str]:
    """Convert any plain text key to a valid 64-bit DES key (16 hex chars).
    
    Returns (key_hex, key_plain_text).
    - If length < 8 chars, pads with spaces.
    - If length > 8 chars, trims to 8 chars.
    - If user explicitly enters 16 hex digits (like 133457799BBCDFF1), preserves it.
    """
    cleaned = key_input.strip()
    if not cleaned:
        cleaned = "SECURITY"

    # Check if this is already an exact 16-hex character standard key
    if len(cleaned) == 16 and re.fullmatch(r"^[0-9a-fA-F]+$", cleaned):
        key_hex = cleaned.upper()
        try:
            plain_text_rep = bytes.fromhex(key_hex).decode('latin-1')
        except Exception:
            plain_text_rep = cleaned
        return key_hex, plain_text_rep

    # Treat as plain text
    raw_bytes = cleaned.encode('utf-8')
    if len(raw_bytes) < 8:
        raw_bytes = raw_bytes.ljust(8, b' ')
    elif len(raw_bytes) > 8:
        raw_bytes = raw_bytes[:8]

    key_hex = raw_bytes.hex().upper()
    try:
        plain_text_rep = raw_bytes.decode('utf-8', errors='replace')
    except Exception:
        plain_text_rep = cleaned[:8]

    return key_hex, plain_text_rep


def validate_key(key_input: str, input_type: str = "auto") -> str:
    """Validate DES key. Always guarantees a valid 16-character hex string representing 64 bits."""
    cleaned = key_input.strip()
    if not cleaned:
        cleaned = "SECURITY"
        
    if input_type == "hex":
        if re.fullmatch(r"^[0-9a-fA-F]{16}$", cleaned):
            return cleaned.upper()
        # Fallback to plain text normalization if not exact 16-hex
        key_hex, _ = normalize_plain_text_key(cleaned)
        return key_hex

    # Default to auto / plain text normalization
    key_hex, _ = normalize_plain_text_key(cleaned)
    return key_hex


def validate_plaintext(plaintext: str, input_type: str = "ascii") -> Tuple[str, str]:
    """Validate plaintext input. Returns (normalized_input, type)."""
    cleaned = plaintext.strip()
    if not cleaned:
        raise ValidationError("Plaintext cannot be empty.", field="plaintext")
    
    if input_type == "hex":
        # Check if actually hex, else fallback to ascii
        if re.fullmatch(r"^[0-9a-fA-F]+$", cleaned.replace(" ", "")):
            cleaned_hex = validate_hex_string(cleaned, field_name="Plaintext Hex")
            return cleaned_hex, "hex"
        return cleaned, "ascii"
    
    # Default is plain text (ascii)
    return cleaned, "ascii"
