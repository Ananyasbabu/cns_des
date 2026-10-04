"""Unit tests for pure plain text encryption and decryption with plain text key."""

import unittest
from backend.utils.validation import validate_key, validate_plaintext
from backend.des.des_encrypt import encrypt_des
from backend.des.des_decrypt import decrypt_des


class TestPlainTextDES(unittest.TestCase):
    def test_plain_text_message_and_key(self):
        """Verify plain text message 'HELLO WORLD' with key 'SECURITY' encrypts and decrypts to exact text."""
        pt = "HELLO WORLD"
        key_input = "SECURITY"
        
        # Normalize key
        key_hex = validate_key(key_input, input_type="auto")
        self.assertEqual(len(key_hex), 16)
        
        # Encrypt
        enc = encrypt_des(pt, key_hex, input_type="ascii")
        self.assertEqual(enc["status"], "success")
        self.assertTrue(len(enc["ciphertext_hex"]) >= 32)
        
        # Decrypt
        dec = decrypt_des(enc["ciphertext_hex"], key_hex)
        self.assertEqual(dec["status"], "success")
        self.assertEqual(dec["recovered_plaintext"], pt)
        self.assertEqual(dec["plaintext_ascii"], pt)
        self.assertTrue(len(dec["recovered_chars"]) == len(pt))

    def test_short_plain_text_key(self):
        """Verify key shorter than 8 chars is automatically space-padded and works smoothly."""
        pt = "STRICT MAAM TEST"
        key_input = "MYKEY" # 5 chars
        
        key_hex = validate_key(key_input, input_type="auto")
        self.assertEqual(len(key_hex), 16)
        
        enc = encrypt_des(pt, key_hex, input_type="ascii")
        dec = decrypt_des(enc["ciphertext_hex"], key_hex)
        self.assertEqual(dec["plaintext_ascii"], pt)


if __name__ == "__main__":
    unittest.main()
