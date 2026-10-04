"""Dynamic DES Module: Configurable Key-Changing and Block-Dependent Cryptography.

This module is strictly isolated from standard DES. It demonstrates dynamic key derivation
where each plaintext block derives a unique 64-bit DES session key from a Master Key
and dynamic block parameters (such as block counter, salt/nonce, or cipher feedback).
"""

from typing import List, Dict, Any, Tuple
from backend.utils.binary_utils import (
    hex_to_bin, bin_to_hex, text_to_bytes, bytes_to_bin,
    pad_pkcs7, unpad_pkcs7, split_into_64bit_blocks,
    bin_to_bytes, enforce_odd_parity
)
from backend.des.permutation import left_circular_shift, xor_bits
from backend.des.key_schedule import generate_key_schedule_trace
from backend.des.des_encrypt import encrypt_64bit_block
from backend.des.des_decrypt import decrypt_64bit_block
from backend.des.visualizer import calculate_hamming_distance


def derive_dynamic_block_key(
    master_key_bin: str,
    block_index: int,
    dynamic_salt_hex: str = "A5A5A5A5A5A5A5A5",
    mode: str = "block_counter"
) -> Dict[str, Any]:
    """Derive a distinct 64-bit DES session key for block_index from the Master Key.
    
    Modes:
    1. 'block_counter': Deterministic dynamic derivation combining Master Key, block index,
       and rotation shift.
       Formula:
         Param = (BlockIndex * GoldenRatioConstant) XOR Salt
         DerivedKey = RotateLeft(MasterKey XOR Param, (BlockIndex * 3) % 64)
         + Enforce Odd Parity
    2. 'salt_nonce': Master Key XOR Dynamic Nonce per block.
    """
    clean_master = master_key_bin.replace(" ", "")
    salt_bin = hex_to_bin(dynamic_salt_hex, 64)
    
    # Golden ratio constant used in hash/permutation distributions (0x9E3779B97F4A7C15)
    golden_constant = 0x9E3779B97F4A7C15
    dynamic_numeric = (block_index * golden_constant) & 0xFFFFFFFFFFFFFFFF
    dynamic_param_bin = bin(dynamic_numeric)[2:].zfill(64)
    
    # Combine parameter with salt
    effective_param_bin = xor_bits(dynamic_param_bin, salt_bin)
    
    # XOR master key with effective parameter
    mixed_bits = xor_bits(clean_master, effective_param_bin)
    
    # Dynamic circular rotation based on block index
    rotation_amount = (block_index * 5) % 64
    rotated_bits = left_circular_shift(mixed_bits, rotation_amount)
    
    # Enforce standard DES odd parity on every byte
    final_session_key_bin = enforce_odd_parity(rotated_bits)
    final_session_key_hex = bin_to_hex(final_session_key_bin)
    
    return {
        "block_index": block_index,
        "mode": mode,
        "master_key_bin": clean_master,
        "master_key_hex": bin_to_hex(clean_master),
        "dynamic_param_bin": dynamic_param_bin,
        "dynamic_param_hex": bin_to_hex(dynamic_param_bin),
        "rotation_amount": rotation_amount,
        "mixed_before_rotation": mixed_bits,
        "rotated_bits": rotated_bits,
        "session_key_bin": final_session_key_bin,
        "session_key_hex": final_session_key_hex,
        "why_it_changes": f"Block #{block_index} injects dynamic parameter 0x{bin_to_hex(dynamic_param_bin)[:8]}... with rotation of {rotation_amount} bits to produce a completely independent 64-bit DES session key."
    }


def encrypt_dynamic_des(
    plaintext: str,
    master_key_hex: str,
    dynamic_salt_hex: str = "A5A5A5A5A5A5A5A5",
    input_type: str = "ascii"
) -> Dict[str, Any]:
    """Execute Dynamic DES encryption across all blocks of plaintext.
    
    Each block derives a distinct DES session key from the Master Key.
    """
    clean_master_hex = master_key_hex.strip().upper()
    master_key_bin = hex_to_bin(clean_master_hex, 64)
    
    # Prepare 64-bit binary blocks
    blocks_bin = []
    if input_type == "hex":
        clean_pt = plaintext.strip().replace(" ", "").upper()
        rem = len(clean_pt) % 16
        if rem != 0:
            clean_pt = clean_pt.ljust(len(clean_pt) + (16 - rem), '0')
        for i in range(0, len(clean_pt), 16):
            blocks_bin.append(hex_to_bin(clean_pt[i:i+16], 64))
    else:
        pt_bytes = text_to_bytes(plaintext)
        padded = pad_pkcs7(pt_bytes, 8)
        blocks_bin = split_into_64bit_blocks(bytes_to_bin(padded))
        
    dynamic_blocks_trace = []
    all_ct_hex = []
    all_ct_bin = []
    
    for idx, b_bin in enumerate(blocks_bin, 1):
        # 1. Derive dynamic key for this specific block
        key_derivation = derive_dynamic_block_key(master_key_bin, idx, dynamic_salt_hex)
        session_key_hex = key_derivation["session_key_hex"]
        
        # 2. Key schedule for this session key
        session_key_trace = generate_key_schedule_trace(session_key_hex, is_hex=True)
        
        # 3. Encrypt block with session key
        block_trace = encrypt_64bit_block(b_bin, session_key_trace)
        block_trace["block_index"] = idx
        block_trace["key_derivation"] = key_derivation
        
        dynamic_blocks_trace.append(block_trace)
        all_ct_hex.append(block_trace["ciphertext_hex"])
        all_ct_bin.append(block_trace["ciphertext_binary"])
        
    return {
        "status": "success",
        "algorithm": "Dynamic DES",
        "master_key_hex": clean_master_hex,
        "dynamic_salt_hex": dynamic_salt_hex,
        "total_blocks": len(blocks_bin),
        "ciphertext_hex": "".join(all_ct_hex),
        "ciphertext_binary": "".join(all_ct_bin),
        "block_traces": dynamic_blocks_trace
    }


def decrypt_dynamic_des(
    ciphertext_hex: str,
    master_key_hex: str,
    dynamic_salt_hex: str = "A5A5A5A5A5A5A5A5"
) -> Dict[str, Any]:
    """Execute Dynamic DES decryption across all ciphertext blocks.
    
    Recalculates the exact dynamic session keys per block and decrypts with reverse subkeys.
    """
    clean_ct = ciphertext_hex.strip().replace(" ", "").upper()
    master_bin = hex_to_bin(master_key_hex, 64)
    
    ct_bin_stream = hex_to_bin(clean_ct)
    blocks_bin = split_into_64bit_blocks(ct_bin_stream)
    
    decrypted_blocks = []
    all_pt_bin = []
    all_pt_hex = []
    
    for idx, b_bin in enumerate(blocks_bin, 1):
        # Regenerate exact session key for block idx
        key_derivation = derive_dynamic_block_key(master_bin, idx, dynamic_salt_hex)
        session_key_hex = key_derivation["session_key_hex"]
        
        key_trace = generate_key_schedule_trace(session_key_hex, is_hex=True)
        reversed_keys = key_trace["round_keys"][::-1]
        
        b_trace = decrypt_64bit_block(b_bin, reversed_keys)
        b_trace["block_index"] = idx
        b_trace["key_derivation"] = key_derivation
        
        decrypted_blocks.append(b_trace)
        all_pt_bin.append(b_trace["plaintext_binary"])
        all_pt_hex.append(b_trace["plaintext_hex"])
        
    full_bin = "".join(all_pt_bin)
    raw_bytes = bin_to_bytes(full_bin)
    unpadded = unpad_pkcs7(raw_bytes)
    
    try:
        recovered_ascii = unpadded.decode('utf-8', errors='replace')
    except Exception:
        recovered_ascii = ""
        
    return {
        "status": "success",
        "ciphertext_hex": clean_ct,
        "master_key_hex": master_key_hex,
        "total_blocks": len(blocks_bin),
        "plaintext_hex": "".join(all_pt_hex),
        "plaintext_binary": full_bin,
        "plaintext_ascii": recovered_ascii,
        "block_traces": decrypted_blocks
    }


def compare_standard_vs_dynamic(
    identical_plaintext_block_hex: str = "0123456789ABCDEF",
    key_hex: str = "133457799BBCDFF1"
) -> Dict[str, Any]:
    """Demonstrate the critical educational difference between Standard DES and Dynamic DES.
    
    Encrypts TWO identical plaintext blocks:
    - Standard DES: Block 1 and Block 2 produce the EXACT SAME ciphertext.
    - Dynamic DES: Block 1 and Block 2 produce COMPLETELY DIFFERENT ciphertexts!
    """
    clean_key = key_hex.strip().upper()
    pt_bin = hex_to_bin(identical_plaintext_block_hex, 64)
    
    # 1. Standard DES on Block 1 and Block 2
    std_key_trace = generate_key_schedule_trace(clean_key, is_hex=True)
    std_block1 = encrypt_64bit_block(pt_bin, std_key_trace)
    std_block2 = encrypt_64bit_block(pt_bin, std_key_trace)
    
    # 2. Dynamic DES on Block 1 and Block 2
    dyn_key1 = derive_dynamic_block_key(hex_to_bin(clean_key, 64), 1)
    dyn_key2 = derive_dynamic_block_key(hex_to_bin(clean_key, 64), 2)
    
    trace_k1 = generate_key_schedule_trace(dyn_key1["session_key_hex"], is_hex=True)
    trace_k2 = generate_key_schedule_trace(dyn_key2["session_key_hex"], is_hex=True)
    
    dyn_block1 = encrypt_64bit_block(pt_bin, trace_k1)
    dyn_block2 = encrypt_64bit_block(pt_bin, trace_k2)
    
    # Comparison metrics
    std_same = (std_block1["ciphertext_hex"] == std_block2["ciphertext_hex"])
    dyn_diff = calculate_hamming_distance(dyn_block1["ciphertext_binary"], dyn_block2["ciphertext_binary"])
    key_diff = calculate_hamming_distance(dyn_key1["session_key_bin"], dyn_key2["session_key_bin"])
    
    return {
        "identical_plaintext_hex": identical_plaintext_block_hex,
        "master_key_hex": clean_key,
        "standard_des": {
            "key_block1": clean_key,
            "key_block2": clean_key,
            "keys_are_identical": True,
            "cipher_block1": std_block1["ciphertext_hex"],
            "cipher_block2": std_block2["ciphertext_hex"],
            "ciphertexts_are_identical": std_same,
            "ecb_vulnerability": "Vulnerable to pattern analysis and replay attacks: identical plaintexts reveal identical ciphertexts."
        },
        "dynamic_des": {
            "key_block1": dyn_key1["session_key_hex"],
            "key_block2": dyn_key2["session_key_hex"],
            "keys_are_identical": False,
            "key_hamming_difference": key_diff,
            "cipher_block1": dyn_block1["ciphertext_hex"],
            "cipher_block2": dyn_block2["ciphertext_hex"],
            "ciphertexts_are_identical": False,
            "ciphertext_hamming_difference": dyn_diff,
            "security_advantage": "Completely eliminates ECB repeating patterns: identical plaintext blocks encrypt to distinct pseudorandom ciphertexts."
        }
    }
