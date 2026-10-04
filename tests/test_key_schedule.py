"""Unit tests for DES Key Schedule, PC-1, Circular Shifts, and PC-2."""

import unittest
from backend.des.tables import PC1, PC2, LEFT_SHIFTS
from backend.des.permutation import permute
from backend.des.key_schedule import generate_key_schedule_trace, generate_round_keys
from backend.utils.binary_utils import hex_to_bin, analyze_parity_bits


class TestKeySchedule(unittest.TestCase):
    """Test suite for Key Generation, PC-1, Shift Schedule, and PC-2."""

    def setUp(self):
        self.key_hex = "133457799BBCDFF1"
        self.key_bin = hex_to_bin(self.key_hex, 64)

    def test_parity_bit_detection(self):
        """Verify parity bit extraction at positions 8, 16, 24, 32, 40, 48, 56, 64."""
        parity_info = analyze_parity_bits(self.key_bin)
        self.assertEqual(len(parity_info), 8)
        positions = [p["parity_position"] for p in parity_info]
        self.assertEqual(positions, [8, 16, 24, 32, 40, 48, 56, 64])

    def test_pc1_permutation_length(self):
        """Verify PC-1 reduces 64 bits to 56 bits."""
        pc1_out = permute(self.key_bin, PC1)
        self.assertEqual(len(pc1_out), 56)

    def test_c0_d0_halves(self):
        """Verify C0 and D0 are each 28 bits."""
        trace = generate_key_schedule_trace(self.key_hex, is_hex=True)
        self.assertEqual(len(trace["c0"]), 28)
        self.assertEqual(len(trace["d0"]), 28)

    def test_shift_schedule_sum(self):
        """Verify sum of 16 circular shifts is 28 bits (full circle)."""
        self.assertEqual(len(LEFT_SHIFTS), 16)
        self.assertEqual(sum(LEFT_SHIFTS), 28)

    def test_pc2_round_keys_count_and_length(self):
        """Verify 16 subkeys are generated, each exactly 48 bits."""
        keys = generate_round_keys(self.key_bin)
        self.assertEqual(len(keys), 16)
        for idx, k in enumerate(keys, 1):
            self.assertEqual(len(k), 48, f"Round key K{idx} must be 48 bits")


if __name__ == "__main__":
    unittest.main()
