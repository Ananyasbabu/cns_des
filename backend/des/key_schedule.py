"""DES Key Schedule: Subkey generation algorithm for 16 rounds."""

from typing import List, Dict, Any, Tuple
from backend.des.tables import PC1, PC1_C, PC1_D, PC2, LEFT_SHIFTS
from backend.des.permutation import permute, left_circular_shift, split_half
from backend.utils.binary_utils import hex_to_bin, bin_to_hex, analyze_parity_bits


def generate_round_keys(key_64_bin: str) -> List[str]:
    """Generate the 16 48-bit subkeys (K1 to K16) from 64-bit key binary string."""
    clean_key = key_64_bin.replace(" ", "")
    # Permuted Choice 1 (64 -> 56 bits)
    key_56 = permute(clean_key, PC1)
    C, D = split_half(key_56)
    
    round_keys = []
    for shift in LEFT_SHIFTS:
        C = left_circular_shift(C, shift)
        D = left_circular_shift(D, shift)
        round_key = permute(C + D, PC2)
        round_keys.append(round_key)
        
    return round_keys


def generate_key_schedule_trace(key_input: str, is_hex: bool = True) -> Dict[str, Any]:
    """Generate detailed educational trace of the entire 16-round key generation process.
    
    Exposes parity bit stripping, PC-1 permutation, C0/D0 splitting,
    round-by-round circular shifts, and PC-2 compression to 48 bits.
    """
    if is_hex:
        key_hex = key_input.strip().upper()
        key_64_bin = hex_to_bin(key_hex, 64)
    else:
        key_64_bin = key_input.strip()
        key_hex = bin_to_hex(key_64_bin)

    parity_info = analyze_parity_bits(key_64_bin)
    
    # Step 1: PC-1 permutation (64 bits -> 56 bits)
    pc1_output = permute(key_64_bin, PC1)
    c0 = permute(key_64_bin, PC1_C)
    d0 = permute(key_64_bin, PC1_D)
    
    current_c = c0
    current_d = d0
    
    rounds_trace = []
    round_keys_list = []
    
    for round_num, shift in enumerate(LEFT_SHIFTS, 1):
        prev_c = current_c
        prev_d = current_d
        
        # Circular left shift
        current_c = left_circular_shift(current_c, shift)
        current_d = left_circular_shift(current_d, shift)
        cd_combined = current_c + current_d
        
        # PC-2 permutation (56 bits -> 48 bits)
        round_key_bin = permute(cd_combined, PC2)
        round_key_hex = bin_to_hex(round_key_bin)
        
        round_keys_list.append(round_key_bin)
        
        rounds_trace.append({
            "round": round_num,
            "shift": shift,
            "c_prev": prev_c,
            "d_prev": prev_d,
            "c_current": current_c,
            "d_current": current_d,
            "cd_combined": cd_combined,
            "round_key_bin": round_key_bin,
            "round_key_hex": round_key_hex
        })
        
    return {
        "key_hex": key_hex,
        "key_64_bin": key_64_bin,
        "parity_analysis": parity_info,
        "pc1_table": PC1,
        "pc1_output": pc1_output,
        "c0": c0,
        "d0": d0,
        "shift_schedule": LEFT_SHIFTS,
        "pc2_table": PC2,
        "rounds": rounds_trace,
        "round_keys": round_keys_list
    }
