"""Unit tests for standard DES encryption, decryption, and test vector compliance."""

import unittest
from backend.des.tables import IP, IP_INV
from backend.des.permutation import permute
from backend.des.des_encrypt import encrypt_des
from backend.des.des_decrypt import decrypt_des
from backend.utils.binary_utils import hex_to_bin, bin_to_hex


class TestDESStandard(unittest.TestCase):
    """Test suite verifying standard DES compliance against official NIST test vectors."""

    def setUp(self):
        # Official standard DES test vector
        self.plaintext_hex = "0123456789ABCDEF"
        self.key_hex = "133457799BBCDFF1"
        self.expected_ciphertext_hex = "85E813540F0AB405"

    def test_official_test_vector_encryption(self):
        """Verify that encryption of 0123456789ABCDEF with 133457799BBCDFF1 produces 85E813540F0AB405."""
        result = encrypt_des(self.plaintext_hex, self.key_hex, input_type="hex")
        self.assertEqual(result["status"], "success")
        self.assertEqual(
            result["ciphertext_hex"],
            self.expected_ciphertext_hex,
            f"Expected {self.expected_ciphertext_hex}, got {result['ciphertext_hex']}"
        )

    def test_official_test_vector_decryption(self):
        """Verify that decryption of 85E813540F0AB405 recovers 0123456789ABCDEF."""
        result = decrypt_des(self.expected_ciphertext_hex, self.key_hex)
        self.assertEqual(result["status"], "success")
        self.assertEqual(
            result["plaintext_hex"],
            self.plaintext_hex,
            f"Expected {self.plaintext_hex}, got {result['plaintext_hex']}"
        )

    def test_ip_and_ip_inverse_cancellation(self):
        """Verify IP_INV(IP(X)) == X for any 64-bit input."""
        test_block_bin = hex_to_bin("AABBCCDDEEFF0011", 64)
        ip_res = permute(test_block_bin, IP)
        recovered = permute(ip_res, IP_INV)
        self.assertEqual(test_block_bin, recovered)

    def test_ascii_encryption_and_decryption_roundtrip(self):
        """Verify ASCII plaintext encrypts and decrypts back to identical text."""
        message = "HELLO DES!"
        key = "133457799BBCDFF1"
        enc = encrypt_des(message, key, input_type="ascii")
        ct_hex = enc["ciphertext_hex"]
        dec = decrypt_des(ct_hex, key)
        self.assertEqual(dec["plaintext_ascii"], message)

    def test_section_29_schema_compliance(self):
        """Verify that encryption result contains all required Section 29 fields."""
        res = encrypt_des(self.plaintext_hex, self.key_hex, input_type="hex")
        required_keys = [
            "plaintext", "binary_plaintext", "initial_permutation",
            "L0", "R0", "pc1_output", "C0", "D0", "round_keys",
            "rounds", "preoutput", "ciphertext_binary", "ciphertext_hex"
        ]
        for k in required_keys:
            self.assertIn(k, res, f"Missing required Section 29 field: {k}")
        self.assertEqual(len(res["rounds"]), 16)
        self.assertEqual(len(res["round_keys"]), 16)


if __name__ == "__main__":
    unittest.main()
