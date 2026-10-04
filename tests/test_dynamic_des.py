"""Unit tests for Dynamic DES key derivation, multi-block encryption, and comparison."""

import unittest
from backend.dynamic.dynamic_des import (
    derive_dynamic_block_key, encrypt_dynamic_des, decrypt_dynamic_des, compare_standard_vs_dynamic
)
from backend.utils.binary_utils import hex_to_bin


class TestDynamicDES(unittest.TestCase):
    """Test suite for Dynamic DES mechanism and comparison against standard DES."""

    def setUp(self):
        self.master_key = "133457799BBCDFF1"
        self.master_bin = hex_to_bin(self.master_key, 64)

    def test_dynamic_key_derivation_differs_per_block(self):
        """Verify that Block 1 and Block 2 derive distinct session keys from the same Master Key."""
        k1 = derive_dynamic_block_key(self.master_bin, 1)
        k2 = derive_dynamic_block_key(self.master_bin, 2)
        
        self.assertNotEqual(k1["session_key_hex"], k2["session_key_hex"])
        self.assertNotEqual(k1["dynamic_param_hex"], k2["dynamic_param_hex"])

    def test_dynamic_des_eliminates_ecb_identical_blocks(self):
        """Verify that identical plaintext blocks result in DIFFERENT ciphertext blocks in Dynamic DES."""
        # Two identical 64-bit blocks
        repeated_plain_hex = "0123456789ABCDEF0123456789ABCDEF"
        enc = encrypt_dynamic_des(repeated_plain_hex, self.master_key, input_type="hex")
        
        block1_ct = enc["block_traces"][0]["ciphertext_hex"]
        block2_ct = enc["block_traces"][1]["ciphertext_hex"]
        
        self.assertNotEqual(block1_ct, block2_ct, "Dynamic DES must not produce identical ciphertext blocks for identical plaintext blocks")

    def test_dynamic_des_encryption_and_decryption_roundtrip(self):
        """Verify that Dynamic DES decryption recovers original message exactly."""
        original_msg = "CONFIDENTIAL DYNAMIC KEY DATA"
        enc = encrypt_dynamic_des(original_msg, self.master_key, input_type="ascii")
        dec = decrypt_dynamic_des(enc["ciphertext_hex"], self.master_key)
        self.assertEqual(dec["plaintext_ascii"], original_msg)

    def test_comparison_analysis(self):
        """Verify comparison module correctly documents standard DES ECB flaw vs Dynamic DES security."""
        comp = compare_standard_vs_dynamic("0123456789ABCDEF", self.master_key)
        self.assertTrue(comp["standard_des"]["ciphertexts_are_identical"])
        self.assertFalse(comp["dynamic_des"]["ciphertexts_are_identical"])
        self.assertGreater(comp["dynamic_des"]["ciphertext_hamming_difference"]["differing_bits"], 0)


if __name__ == "__main__":
    unittest.main()
