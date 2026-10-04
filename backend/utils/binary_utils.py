"""Binary and Hexadecimal Utility Functions for DES Educational Visualizer."""

from typing import List, Dict, Any, Tuple


def hex_to_bin(hex_str: str, bit_length: int = None) -> str:
    """Convert hexadecimal string to binary bit string with optional zero-padding."""
    cleaned = hex_str.strip().replace(" ", "").replace("0x", "").replace("0X", "")
    if not cleaned:
        return ""
    # Calculate exact bit length if not specified: 4 bits per hex character
    target_len = bit_length if bit_length is not None else len(cleaned) * 4
    # Parse integer and format to binary string
    val = int(cleaned, 16)
    return bin(val)[2:].zfill(target_len)


def bin_to_hex(bin_str: str) -> str:
    """Convert binary bit string to uppercase hexadecimal string."""
    cleaned = bin_str.replace(" ", "")
    if not cleaned:
        return ""
    # Pad to multiple of 4 bits if needed
    remainder = len(cleaned) % 4
    if remainder != 0:
        cleaned = cleaned.zfill(len(cleaned) + (4 - remainder))
    hex_len = len(cleaned) // 4
    val = int(cleaned, 2)
    return hex(val)[2:].upper().zfill(hex_len)


def text_to_bytes(text: str) -> bytes:
    """Convert text string to UTF-8 bytes."""
    return text.encode('utf-8')


def bytes_to_bin(byte_data: bytes) -> str:
    """Convert bytes to binary string."""
    return "".join(f"{b:08b}" for b in byte_data)


def bin_to_bytes(bin_str: str) -> bytes:
    """Convert binary bit string into bytes."""
    cleaned = bin_str.replace(" ", "")
    byte_chunks = [cleaned[i:i+8] for i in range(0, len(cleaned), 8)]
    return bytes(int(chunk, 2) for chunk in byte_chunks if len(chunk) == 8)


def format_bit_groups(bit_str: str, group_size: int = 8, separator: str = " ") -> str:
    """Format bit string into visually grouped chunks (e.g. 8 bits for bytes, 4 bits for hex)."""
    cleaned = bit_str.replace(" ", "")
    chunks = [cleaned[i:i+group_size] for i in range(0, len(cleaned), group_size)]
    return separator.join(chunks)


def pad_pkcs7(data_bytes: bytes, block_size: int = 8) -> bytes:
    """Apply standard PKCS#7 padding to align data to block_size (default 8 bytes = 64 bits)."""
    pad_len = block_size - (len(data_bytes) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data_bytes + bytes([pad_len] * pad_len)


def unpad_pkcs7(padded_bytes: bytes) -> bytes:
    """Remove PKCS#7 padding safely."""
    if not padded_bytes:
        return b""
    pad_len = padded_bytes[-1]
    if pad_len < 1 or pad_len > 8:
        # If padding format is invalid, return raw bytes
        return padded_bytes
    # Check that all padding bytes match
    if padded_bytes[-pad_len:] == bytes([pad_len] * pad_len):
        return padded_bytes[:-pad_len]
    return padded_bytes


def split_into_64bit_blocks(bin_str: str) -> List[str]:
    """Split a continuous binary string into a list of 64-bit block strings."""
    cleaned = bin_str.replace(" ", "")
    blocks = []
    for i in range(0, len(cleaned), 64):
        chunk = cleaned[i:i+64]
        if len(chunk) == 64:
            blocks.append(chunk)
    return blocks


def analyze_parity_bits(key_64_bin: str) -> List[Dict[str, Any]]:
    """Analyze parity bits at positions 8, 16, 24, 32, 40, 48, 56, 64 in standard DES.
    
    DES specifies odd parity: the sum of the 8 bits in each byte should be odd.
    These 8 bits are discarded by PC-1 permutation to yield the 56-bit effective key.
    """
    cleaned = key_64_bin.replace(" ", "")
    results = []
    for byte_idx in range(8):
        byte_bits = cleaned[byte_idx*8 : (byte_idx+1)*8]
        data_bits = byte_bits[:7]
        parity_bit = byte_bits[7]
        ones_count = byte_bits.count('1')
        is_odd = (ones_count % 2 == 1)
        expected_parity = '1' if (data_bits.count('1') % 2 == 0) else '0'
        
        results.append({
            "byte_index": byte_idx + 1,
            "bits": byte_bits,
            "data_bits": data_bits,
            "parity_bit": parity_bit,
            "parity_position": (byte_idx + 1) * 8,
            "total_ones": ones_count,
            "is_odd_parity": is_odd,
            "expected_parity_bit": expected_parity,
            "discarded_by_pc1": True
        })
    return results


def enforce_odd_parity(key_64_bin: str) -> str:
    """Adjust the parity bits (8th bit of each byte) to guarantee odd parity."""
    cleaned = key_64_bin.replace(" ", "")
    adjusted = []
    for byte_idx in range(8):
        byte_bits = cleaned[byte_idx*8 : (byte_idx+1)*8]
        data_bits = byte_bits[:7]
        parity_bit = '1' if (data_bits.count('1') % 2 == 0) else '0'
        adjusted.append(data_bits + parity_bit)
    return "".join(adjusted)
