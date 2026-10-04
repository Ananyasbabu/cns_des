"""Unit tests for S-box substitution logic, row/column extraction, and output length."""

import unittest
from backend.des.sbox import substitute_single_box, sbox_substitution
from backend.des.tables import S_BOXES


class TestSBox(unittest.TestCase):
    """Test suite for S-Box substitution mechanisms."""

    def test_prompt_specified_sbox_example(self):
        """Verify the exact example from the project specification:
        Input: 011011 to S1
        Row: first bit (0) + last bit (1) = 01 (Row 1)
        Column: middle bits (1101) = 13 (Column 13)
        S1[1][13] = 5 -> 4-bit output '0101'
        """
        res = substitute_single_box(0, "011011")
        self.assertEqual(res["box_num"], 1)
        self.assertEqual(res["row_bits"], "01")
        self.assertEqual(res["row"], 1)
        self.assertEqual(res["col_bits"], "1101")
        self.assertEqual(res["col"], 13)
        self.assertEqual(res["value"], 5)
        self.assertEqual(res["output_bits"], "0101")
        self.assertEqual(res["output_hex"], "5")

    def test_all_sboxes_dimension_and_range(self):
        """Verify all 8 S-Boxes have 4 rows and 16 columns with values 0 to 15."""
        self.assertEqual(len(S_BOXES), 8)
        for box_idx, box in enumerate(S_BOXES, 1):
            self.assertEqual(len(box), 4, f"S-Box {box_idx} must have 4 rows")
            for row_idx, row in enumerate(box):
                self.assertEqual(len(row), 16, f"S-Box {box_idx} row {row_idx} must have 16 columns")
                for val in row:
                    self.assertTrue(0 <= val <= 15, f"S-Box {box_idx} value {val} out of 4-bit range")

    def test_full_48bit_sbox_substitution_length(self):
        """Verify 48-bit input produces exactly 32-bit output from 8 boxes."""
        test_48 = "011011" * 8
        out_32, box_details = sbox_substitution(test_48)
        self.assertEqual(len(out_32), 32)
        self.assertEqual(len(box_details), 8)


if __name__ == "__main__":
    unittest.main()
