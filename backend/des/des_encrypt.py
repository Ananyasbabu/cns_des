"""Complete 16-Round DES Encryption Engine with Comprehensive Trace Generation."""

from typing import List, Dict, Any, Union
from backend.des.tables import IP, IP_INV
from backend.des.permutation import permute, split_half
from backend.des.key_schedule import generate_round_keys, generate_key_schedule_trace
from backend.des.round_function import execute_des_round
from backend.utils.binary_utils import (
    hex_to_bin, bin_to_hex, text_to_bytes, bytes_to_bin, bin_to_bytes,
    pad_pkcs7, split_into_64bit_blocks
)


def encrypt_64bit_block(plaintext_64_bin: str, key_schedule_info: Dict[str, Any]) -> Dict[str, Any]:
    """Perform full 16-round DES encryption on a single 64-bit binary block.
    
    Generates structured educational trace of:
    - Input block
    - Initial Permutation (IP)
    - L0 and R0 split
    - Rounds 1 through 16 (Li, Ri, Feistel expansion, XOR, S-Boxes, P-Box)
    - 32-bit Swap after Round 16 (R16 || L16)
    - Inverse Initial Permutation (IP^-1)
    - Final Ciphertext (binary and hex)
    """
    clean_pt = plaintext_64_bin.replace(" ", "")
    if len(clean_pt) != 64:
        raise ValueError(f"Block size must be exactly 64 bits, got {len(clean_pt)}")
        
    # Step 1: Initial Permutation (IP)
    ip_output = permute(clean_pt, IP)
    
    # Step 2: Split into L0 and R0
    l0, r0 = split_half(ip_output)
    
    # Step 3: 16 Feistel Rounds
    current_l = l0
    current_r = r0
    rounds_trace = []
    
    round_keys = key_schedule_info["round_keys"]
    
    for round_num in range(1, 17):
        k_round = round_keys[round_num - 1]
        round_data = execute_des_round(round_num, current_l, current_r, k_round)
        rounds_trace.append(round_data)
        
        current_l = round_data["L_current"]
        current_r = round_data["R_current"]
        
    # Step 4: 32-bit swap after Round 16 (Preoutput: R16 || L16)
    # Important: In DES, R16 and L16 are concatenated in reverse order before IP^-1
    preoutput = current_r + current_l
    
    # Step 5: Final Permutation (IP^-1)
    ciphertext_bin = permute(preoutput, IP_INV)
    ciphertext_hex = bin_to_hex(ciphertext_bin)
    
    return {
        "plaintext_block_bin": clean_pt,
        "plaintext_block_hex": bin_to_hex(clean_pt),
        "ip_table": IP,
        "initial_permutation": ip_output,
        "L0": l0,
        "R0": r0,
        "rounds": rounds_trace,
        "l16": current_l,
        "r16": current_r,
        "preoutput_unswapped": current_l + current_r,
        "preoutput": preoutput,
        "ip_inv_table": IP_INV,
        "ciphertext_binary": ciphertext_bin,
        "ciphertext_hex": ciphertext_hex
    }


def encrypt_des(plaintext: str, key_hex: str, input_type: str = "hex") -> Dict[str, Any]:
    """High-level DES encryption API supporting both ASCII text and Hexadecimal input.
    
    Returns complete structured JSON conforming to Section 29 requirements.
    """
    clean_key_hex = key_hex.strip().upper()
    key_64_bin = hex_to_bin(clean_key_hex, 64)
    key_trace = generate_key_schedule_trace(clean_key_hex, is_hex=True)
    
    blocks_bin = []
    raw_ascii = ""
    
    if input_type == "hex":
        clean_pt_hex = plaintext.strip().replace(" ", "").upper()
        # If hex length is not multiple of 16, pad with zeros to 64-bit boundary
        remainder = len(clean_pt_hex) % 16
        if remainder != 0:
            clean_pt_hex = clean_pt_hex.ljust(len(clean_pt_hex) + (16 - remainder), '0')
        for i in range(0, len(clean_pt_hex), 16):
            chunk = clean_pt_hex[i:i+16]
            blocks_bin.append(hex_to_bin(chunk, 64))
    else:
        # ASCII text: Apply PKCS#7 padding to 8-byte blocks
        raw_ascii = plaintext
        pt_bytes = text_to_bytes(plaintext)
        padded_bytes = pad_pkcs7(pt_bytes, 8)
        bin_stream = bytes_to_bin(padded_bytes)
        blocks_bin = split_into_64bit_blocks(bin_stream)

    block_traces = []
    all_ciphertext_hex = []
    all_ciphertext_bin = []
    
    for idx, block_bin in enumerate(blocks_bin):
        b_trace = encrypt_64bit_block(block_bin, key_trace)
        b_trace["block_index"] = idx + 1
        block_traces.append(b_trace)
        all_ciphertext_hex.append(b_trace["ciphertext_hex"])
        all_ciphertext_bin.append(b_trace["ciphertext_binary"])
        
    primary_block = block_traces[0]
    
    # Format round_keys for Section 29 compatibility
    formatted_round_keys = []
    for r in key_trace["rounds"]:
        formatted_round_keys.append({
            "round": r["round"],
            "shift": r["shift"],
            "C": r["c_current"],
            "D": r["d_current"],
            "key": r["round_key_bin"],
            "key_hex": r["round_key_hex"]
        })

    # Character-by-character ASCII breakdown for educational clarity
    pt_breakdown = []
    for ch in plaintext:
        code = ord(ch)
        pt_breakdown.append({
            "char": ch if ch != " " else "(space)",
            "ascii": code,
            "bin": bin(code)[2:].zfill(8)
        })

    key_bytes = bin_to_bytes(key_64_bin)
    key_breakdown = []
    for b in key_bytes:
        char_rep = chr(b) if 32 <= b <= 126 else f"\\x{b:02X}"
        key_breakdown.append({
            "char": char_rep,
            "ascii": b,
            "bin": bin(b)[2:].zfill(8)
        })

    try:
        key_plain = key_bytes.decode('utf-8', errors='replace')
    except Exception:
        key_plain = clean_key_hex
        
    # Assemble master response
    return {
        "status": "success",
        "input_type": input_type,
        "raw_plaintext": plaintext,
        "plaintext_display": plaintext,
        "key_display": key_plain,
        "raw_ascii": raw_ascii,
        "plaintext_breakdown": pt_breakdown,
        "key_breakdown": key_breakdown,
        "total_blocks": len(blocks_bin),
        "key_hex": clean_key_hex,
        "key_binary": key_64_bin,
        "parity_analysis": key_trace["parity_analysis"],
        "pc1_output": key_trace["pc1_output"],
        "C0": key_trace["c0"],
        "D0": key_trace["d0"],
        "round_keys": formatted_round_keys,
        # Primary block fields (Block 1) for seamless single-block visualizer inspection
        "plaintext": primary_block["plaintext_block_hex"],
        "binary_plaintext": primary_block["plaintext_block_bin"],
        "initial_permutation": primary_block["initial_permutation"],
        "L0": primary_block["L0"],
        "R0": primary_block["R0"],
        "rounds": primary_block["rounds"],
        "preoutput": primary_block["preoutput"],
        "ciphertext_binary": "".join(all_ciphertext_bin),
        "ciphertext_hex": "".join(all_ciphertext_hex),
        "block_traces": block_traces
    }
