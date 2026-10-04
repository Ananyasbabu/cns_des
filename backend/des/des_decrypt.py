"""DES Decryption Engine using Reverse Round-Key Order (K16 -> K1)."""

from typing import List, Dict, Any
from backend.des.tables import IP, IP_INV
from backend.des.permutation import permute, split_half
from backend.des.key_schedule import generate_round_keys, generate_key_schedule_trace
from backend.des.round_function import execute_des_round
from backend.utils.binary_utils import (
    hex_to_bin, bin_to_hex, bin_to_bytes, unpad_pkcs7, split_into_64bit_blocks
)


def decrypt_64bit_block(ciphertext_64_bin: str, reversed_round_keys: List[str]) -> Dict[str, Any]:
    """Execute full 16-round DES decryption on a single 64-bit block using reversed subkeys."""
    clean_ct = ciphertext_64_bin.replace(" ", "")
    if len(clean_ct) != 64:
        raise ValueError(f"Ciphertext block size must be 64 bits, got {len(clean_ct)}")
        
    # Step 1: Initial Permutation (IP)
    ip_output = permute(clean_ct, IP)
    
    # Step 2: Split into L0 and R0
    l0, r0 = split_half(ip_output)
    
    current_l = l0
    current_r = r0
    rounds_trace = []
    
    # 16 Feistel rounds with reversed keys K16, K15, ..., K1
    for round_num in range(1, 17):
        k_round = reversed_round_keys[round_num - 1]
        actual_key_index = 17 - round_num
        round_data = execute_des_round(round_num, current_l, current_r, k_round)
        round_data["decryption_key_number"] = actual_key_index
        rounds_trace.append(round_data)
        
        current_l = round_data["L_current"]
        current_r = round_data["R_current"]
        
    # Step 4: 32-bit swap after round 16 (R16 || L16)
    preoutput = current_r + current_l
    
    # Step 5: Final Inverse Permutation (IP^-1)
    recovered_pt_bin = permute(preoutput, IP_INV)
    recovered_pt_hex = bin_to_hex(recovered_pt_bin)
    
    return {
        "ciphertext_block_bin": clean_ct,
        "ciphertext_block_hex": bin_to_hex(clean_ct),
        "initial_permutation": ip_output,
        "L0": l0,
        "R0": r0,
        "rounds": rounds_trace,
        "preoutput": preoutput,
        "plaintext_binary": recovered_pt_bin,
        "plaintext_hex": recovered_pt_hex
    }


def decrypt_des(ciphertext_hex: str, key_hex: str) -> Dict[str, Any]:
    """Execute full DES decryption on hexadecimal ciphertext.
    
    Demonstrates the Feistel property: identical algorithm as encryption
    except the subkeys are applied in exact reverse order (K16 down to K1).
    """
    clean_ct_hex = ciphertext_hex.strip().replace(" ", "").upper()
    clean_key_hex = key_hex.strip().upper()
    
    # Generate subkeys K1..K16
    key_trace = generate_key_schedule_trace(clean_key_hex, is_hex=True)
    forward_keys = key_trace["round_keys"]
    reversed_keys = forward_keys[::-1]
    
    # Split ciphertext into 64-bit blocks
    ct_bin_full = hex_to_bin(clean_ct_hex)
    blocks_bin = split_into_64bit_blocks(ct_bin_full)
    
    if not blocks_bin:
        raise ValueError("Ciphertext must contain at least one 64-bit (16 hex chars) block.")
        
    block_traces = []
    all_pt_bin = []
    all_pt_hex = []
    
    for idx, b_bin in enumerate(blocks_bin):
        b_trace = decrypt_64bit_block(b_bin, reversed_keys)
        b_trace["block_index"] = idx + 1
        block_traces.append(b_trace)
        all_pt_bin.append(b_trace["plaintext_binary"])
        all_pt_hex.append(b_trace["plaintext_hex"])
        
    primary_block = block_traces[0]
    recovered_bin_str = "".join(all_pt_bin)
    recovered_hex_str = "".join(all_pt_hex)
    
    # Try ASCII decoding
    recovered_bytes = bin_to_bytes(recovered_bin_str)
    unpadded_bytes = unpad_pkcs7(recovered_bytes)
    try:
        recovered_ascii = unpadded_bytes.decode('utf-8', errors='replace')
    except Exception:
        recovered_ascii = ""
        
    return {
        "status": "success",
        "ciphertext_hex": clean_ct_hex,
        "key_hex": clean_key_hex,
        "total_blocks": len(blocks_bin),
        "reversed_keys_order": [f"K{17-i}" for i in range(1, 17)],
        "plaintext_hex": recovered_hex_str,
        "plaintext_binary": recovered_bin_str,
        "plaintext_ascii": recovered_ascii,
        "primary_block": primary_block,
        "block_traces": block_traces
    }
