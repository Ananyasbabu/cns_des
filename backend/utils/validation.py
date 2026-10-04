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


def validate_key(key_input: str, input_type: str = "hex") -> str:
    """Validate 64-bit DES key. Returns cleaned 16-character hexadecimal string."""
    cleaned = key_input.strip()
    if not cleaned:
        raise ValidationError("DES Key is required.", field="key")
    
    if input_type == "hex":
        return validate_hex_string(cleaned, expected_length=16, field_name="DES Key")
    elif input_type == "ascii":
        if len(cleaned) != 8:
            raise ValidationError(
                f"ASCII Key must be exactly 8 characters (64 bits). Received {len(cleaned)} characters.",
                field="key"
            )
        return cleaned.encode('utf-8').hex().upper()
    else:
        raise ValidationError(f"Invalid key input type: {input_type}", field="key_type")


def validate_plaintext(plaintext: str, input_type: str = "ascii") -> Tuple[str, str]:
    """Validate plaintext input. Returns (normalized_input, type)."""
    cleaned = plaintext.strip()
    if not cleaned:
        raise ValidationError("Plaintext cannot be empty.", field="plaintext")
    
    if input_type == "hex":
        cleaned_hex = validate_hex_string(cleaned, field_name="Plaintext Hex")
        # In hex mode, if not multiple of 16 (64 bits), ensure user is notified or pad
        if len(cleaned_hex) % 16 != 0:
            raise ValidationError(
                f"Plaintext Hex must be a multiple of 16 hex digits (64-bit blocks). "
                f"Received {len(cleaned_hex)} hex characters.",
                field="plaintext"
            )
        return cleaned_hex, "hex"
    elif input_type == "ascii":
        return cleaned, "ascii"
    else:
        raise ValidationError(f"Unknown plaintext input type: {input_type}", field="input_type")
