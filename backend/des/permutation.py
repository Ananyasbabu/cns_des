"""Permutation, rotation, and bitwise operations for DES."""

from typing import List, Dict, Any, Tuple


def permute(bits: str, table: List[int]) -> str:
    """Permute a bit string according to a 1-indexed permutation table.
    
    table[i] gives the 1-based position in 'bits' that moves to position i in the output.
    """
    clean_bits = bits.replace(" ", "")
    return "".join(clean_bits[pos - 1] for pos in table)


def permute_with_trace(bits: str, table: List[int], table_name: str = "Permutation") -> Dict[str, Any]:
    """Perform permutation and return educational step trace showing input->output bit mapping."""
    clean_bits = bits.replace(" ", "")
    output_bits = "".join(clean_bits[pos - 1] for pos in table)
    
    mappings = []
    for out_idx, in_pos in enumerate(table):
        mappings.append({
            "out_index": out_idx + 1,
            "in_pos": in_pos,
            "bit": clean_bits[in_pos - 1]
        })
        
    return {
        "table_name": table_name,
        "input_bits": clean_bits,
        "input_len": len(clean_bits),
        "output_bits": output_bits,
        "output_len": len(output_bits),
        "table": table,
        "mappings": mappings
    }


def left_circular_shift(bits: str, n: int) -> str:
    """Perform circular left shift by n positions on a binary string."""
    clean_bits = bits.replace(" ", "")
    n = n % len(clean_bits)
    return clean_bits[n:] + clean_bits[:n]


def right_circular_shift(bits: str, n: int) -> str:
    """Perform circular right shift by n positions on a binary string."""
    clean_bits = bits.replace(" ", "")
    n = n % len(clean_bits)
    return clean_bits[-n:] + clean_bits[:-n]


def xor_bits(bits_a: str, bits_b: str) -> str:
    """Compute bitwise XOR between two equal-length binary strings."""
    clean_a = bits_a.replace(" ", "")
    clean_b = bits_b.replace(" ", "")
    if len(clean_a) != len(clean_b):
        raise ValueError(f"XOR length mismatch: {len(clean_a)} bits vs {len(clean_b)} bits")
    return "".join('1' if a != b else '0' for a, b in zip(clean_a, clean_b))


def split_half(bits: str) -> Tuple[str, str]:
    """Split a binary string into two equal halves (L, R or C, D)."""
    clean = bits.replace(" ", "")
    mid = len(clean) // 2
    return clean[:mid], clean[mid:]
