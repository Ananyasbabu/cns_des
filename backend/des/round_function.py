"""DES Feistel Round Function F(R, K) and Round Execution Engine."""

from typing import Dict, Any
from backend.des.tables import E_EXPANSION, P_PERMUTATION
from backend.des.permutation import permute, xor_bits
from backend.des.sbox import sbox_substitution


def feistel_function(r_prev_32: str, round_key_48: str) -> Dict[str, Any]:
    """Execute the Feistel function F(R_{i-1}, K_i).
    
    Steps:
    1. Expansion Permutation E: 32 bits -> 48 bits
    2. Key XOR: 48-bit expanded R XOR 48-bit round key K_i
    3. S-Box Substitution: 48 bits -> 32 bits across 8 S-Boxes (S1 to S8)
    4. Permutation P: 32 bits -> 32 bits
    """
    clean_r = r_prev_32.replace(" ", "")
    clean_key = round_key_48.replace(" ", "")
    
    # 1. Expansion E (32 -> 48 bits)
    expanded_r = permute(clean_r, E_EXPANSION)
    
    # 2. XOR with Round Key (48 bits)
    xor_result = xor_bits(expanded_r, clean_key)
    
    # 3. S-Box Substitution (48 -> 32 bits)
    sbox_out_32, sbox_details = sbox_substitution(xor_result)
    
    # 4. Straight Permutation P (32 -> 32 bits)
    pbox_out_32 = permute(sbox_out_32, P_PERMUTATION)
    
    return {
        "r_input_32": clean_r,
        "round_key_48": clean_key,
        "e_table": E_EXPANSION,
        "expanded_r_48": expanded_r,
        "xor_result_48": xor_result,
        "sbox_details": sbox_details,
        "sbox_output_32": sbox_out_32,
        "p_table": P_PERMUTATION,
        "pbox_output_32": pbox_out_32,
        "f_output_32": pbox_out_32
    }


def execute_des_round(round_num: int, l_prev_32: str, r_prev_32: str, round_key_48: str) -> Dict[str, Any]:
    """Execute a single complete DES Feistel round.
    
    Formulas:
      L_i = R_{i-1}
      R_i = L_{i-1} XOR F(R_{i-1}, K_i)
    """
    clean_l_prev = l_prev_32.replace(" ", "")
    clean_r_prev = r_prev_32.replace(" ", "")
    clean_key = round_key_48.replace(" ", "")
    
    # Run Feistel function F
    f_trace = feistel_function(clean_r_prev, clean_key)
    f_result = f_trace["f_output_32"]
    
    # Standard DES round outputs
    l_curr = clean_r_prev
    r_curr = xor_bits(clean_l_prev, f_result)
    
    return {
        "round": round_num,
        "l_prev": clean_l_prev,
        "r_prev": clean_r_prev,
        "round_key": clean_key,
        "feistel": f_trace,
        # Flattened convenience fields matching Section 29 JSON schema
        "L_previous": clean_l_prev,
        "R_previous": clean_r_prev,
        "expanded_R": f_trace["expanded_r_48"],
        "xor_result": f_trace["xor_result_48"],
        "sboxes": f_trace["sbox_details"],
        "sbox_output": f_trace["sbox_output_32"],
        "pbox_output": f_trace["pbox_output_32"],
        "L_current": l_curr,
        "R_current": r_curr
    }
