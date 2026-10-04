"""Educational Visualizer Utilities and Presentation Mode Annotations for DES."""

from typing import Dict, Any, List


STEP_PRESENTATION_EXPLANATIONS = {
    "step1_plaintext": {
        "title": "Step 1: Plaintext to Binary Block Formation",
        "concept": "Digital data is converted into raw binary bits and partitioned into fixed 64-bit blocks.",
        "academic_note": "DES is a 64-bit symmetric block cipher. If plaintext is ASCII text, each character is represented by 8 bits (1 byte). Padding (PKCS#7) ensures the last block is exactly 64 bits.",
        "formula": "Block = [b1, b2, ..., b64]"
    },
    "step2_key_processing": {
        "title": "Step 2: Key Ingestion & PC-1 Permutation",
        "concept": "The 64-bit user key is compressed into a 56-bit effective key via Permuted Choice 1 (PC-1).",
        "academic_note": "Every 8th bit (positions 8, 16, 24, 32, 40, 48, 56, 64) is a parity check bit and is completely discarded by PC-1. Hence, DES provides an effective security level of only 56 bits.",
        "formula": "K_{56} = PC1(K_{64}), \\quad C_0 = \\text{MSB}_{28}(K_{56}), \\quad D_0 = \\text{LSB}_{28}(K_{56})"
    },
    "step3_round_keys": {
        "title": "Step 3: Key Schedule & 16 Subkey Generation",
        "concept": "Halves C and D undergo circular left shifts, then Permuted Choice 2 (PC-2) generates a 48-bit subkey Ki for each round.",
        "academic_note": "Rounds 1, 2, 9, 16 use 1-bit circular shifts; the remaining 12 rounds use 2-bit shifts. Total shifts = 4×1 + 12×2 = 28 bits, completing a full circle.",
        "formula": "C_i = \\text{LS}_{s_i}(C_{i-1}), \\quad D_i = \\text{LS}_{s_i}(D_{i-1}), \\quad K_i = PC2(C_i \\parallel D_i)"
    },
    "step4_initial_permutation": {
        "title": "Step 4: Initial Permutation (IP)",
        "concept": "The 64-bit plaintext block undergoes a fixed bitwise transposition.",
        "academic_note": "IP does NOT provide cryptographic security; it was historically designed to facilitate 8-bit bus transfers in 1970s hardware. It rearranges bits so that even bits go to one half and odd bits go to the other.",
        "formula": "[L_0, R_0] = \\text{Split}_{32}(IP(\\text{Plaintext}))"
    },
    "step5_feistel_round": {
        "title": "Step 5: 16-Round Feistel Network",
        "concept": "Data is iteratively scrambled across 16 symmetric rounds using the Feistel round function F.",
        "academic_note": "Feistel architecture guarantees reversibility: encryption and decryption use the identical algorithm, requiring only reversed round keys.",
        "formula": "L_i = R_{i-1}, \\quad R_i = L_{i-1} \\oplus F(R_{i-1}, K_i)"
    },
    "step6_expansion": {
        "title": "Step 6: Expansion Permutation E",
        "concept": "The 32-bit right half is expanded to 48 bits by duplicating 16 edge bits.",
        "academic_note": "Expansion enables 32-bit data to match the 48-bit subkey size and ensures each bit influences multiple S-box substitutions, providing rapid avalanche diffusion.",
        "formula": "E(R_{i-1}) \\in \\{0, 1\\}^{48}"
    },
    "step7_key_xor": {
        "title": "Step 7: Subkey XOR Mixing",
        "concept": "The 48-bit expanded right half is combined with the 48-bit round subkey Ki using bitwise XOR.",
        "academic_note": "XOR injects the secret key material directly into the data path. In binary arithmetic, XOR is addition modulo 2 without carry.",
        "formula": "A = E(R_{i-1}) \\oplus K_i"
    },
    "step8_sboxes": {
        "title": "Step 8: S-Box Substitution (Confusion)",
        "concept": "The 48-bit XOR stream is divided into 8 groups of 6 bits. Each group is substituted by a non-linear 4-bit output.",
        "academic_note": "S-boxes provide the ONLY non-linear operation in standard DES. Without S-boxes, DES would be a system of linear equations easily broken by Gaussian elimination.",
        "formula": "\\text{Row} = (b_1 b_6)_2, \\quad \\text{Col} = (b_2 b_3 b_4 b_5)_2, \\quad B_i = S_i[\\text{Row}][\\text{Col}]"
    },
    "step9_pbox": {
        "title": "Step 9: Straight P-Box Permutation (Diffusion)",
        "concept": "The 32 bits from the 8 S-boxes are permuted across bit positions.",
        "academic_note": "P-box ensures that the 4 output bits of each S-box are distributed across 4 different S-boxes in the subsequent round, maximizing the avalanche effect.",
        "formula": "F(R_{i-1}, K_i) = P(S_1(B_1) \\parallel \\dots \\parallel S_8(B_8))"
    },
    "step10_swap": {
        "title": "Step 10: 32-Bit Halves Swap",
        "concept": "After Round 16, L16 and R16 are concatenated in reverse order: R16 || L16.",
        "academic_note": "The pre-output swap cancels out the final swap of the Feistel structure, making the decryption algorithm identical to encryption.",
        "formula": "\\text{Preoutput} = R_{16} \\parallel L_{16}"
    },
    "step11_final_permutation": {
        "title": "Step 11: Inverse Initial Permutation (IP^-1)",
        "concept": "The swapped 64-bit preoutput undergoes the exact inverse permutation of IP.",
        "academic_note": "IP^-1 is mathematically the inverse of IP: IP^-1(IP(x)) = x. It produces the final 64-bit ciphertext.",
        "formula": "\\text{Ciphertext} = IP^{-1}(R_{16} \\parallel L_{16})"
    },
    "step12_decryption": {
        "title": "Step 12: Symmetric Decryption",
        "concept": "Ciphertext is decrypted through the identical 16 Feistel rounds using subkeys in reverse order (K16 down to K1).",
        "academic_note": "Because L_i = R_{i-1} and R_i = L_{i-1} XOR F(R_{i-1}, K_i), passing R16 and L16 with K16 computes R15 and L15 without needing an inverse F function!",
        "formula": "\\text{Plaintext} = \\text{DES}_{K_{16}\\dots K_1}(\\text{Ciphertext})"
    },
    "step13_dynamic_des": {
        "title": "Step 13: Dynamic Changing Mechanism",
        "concept": "Instead of reusing the same static key across all blocks, each block derives a distinct dynamic session key.",
        "academic_note": "Standard DES in ECB mode encrypts identical plaintext blocks to identical ciphertext blocks. Dynamic DES injects block index or feedback parameters to break repeating patterns.",
        "formula": "K_{\\text{block}}^{(i)} = \\text{DeriveKey}(K_{\\text{master}}, i, \\text{Param})"
    }
}


def calculate_hamming_distance(bits1: str, bits2: str) -> Dict[str, Any]:
    """Calculate bit-level difference (Hamming distance) and avalanche percentage between two bit strings."""
    clean1 = bits1.replace(" ", "")
    clean2 = bits2.replace(" ", "")
    min_len = min(len(clean1), len(clean2))
    
    diff_count = sum(1 for i in range(min_len) if clean1[i] != clean2[i])
    percentage = (diff_count / min_len * 100) if min_len > 0 else 0.0
    
    return {
        "total_bits": min_len,
        "differing_bits": diff_count,
        "avalanche_percentage": round(percentage, 2)
    }
