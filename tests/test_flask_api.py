"""Integration test for Flask REST API endpoints and static frontend serving."""

import unittest
import json
from app import app


class TestFlaskApp(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_index_route(self):
        """Verify root route returns 200 and serves HTML."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Dynamic DES", response.data)

    def test_status_endpoint(self):
        """Verify /api/status returns correct metadata."""
        response = self.client.get('/api/status')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "online")
        self.assertEqual(data["rounds"], 16)

    def test_tables_endpoint(self):
        """Verify /api/tables returns standard tables."""
        response = self.client.get('/api/tables')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data["ip"]), 64)
        self.assertEqual(len(data["s_boxes"]), 8)

    def test_test_vector_endpoint(self):
        """Verify /api/test-vector matches standard NIST output."""
        response = self.client.get('/api/test-vector')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["is_verified"])
        self.assertEqual(data["computed_ciphertext_hex"], "85E813540F0AB405")

    def test_des_encrypt_api(self):
        """Verify POST /api/des/encrypt works as expected."""
        payload = {
            "plaintext": "0123456789ABCDEF",
            "key": "133457799BBCDFF1",
            "input_type": "hex"
        }
        response = self.client.post('/api/des/encrypt', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["ciphertext_hex"], "85E813540F0AB405")

    def test_des_decrypt_api(self):
        """Verify POST /api/des/decrypt recovers plaintext."""
        payload = {
            "ciphertext": "85E813540F0AB405",
            "key": "133457799BBCDFF1"
        }
        response = self.client.post('/api/des/decrypt', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["plaintext_hex"], "0123456789ABCDEF")

    def test_comparison_api(self):
        """Verify POST /api/comparison compares standard vs dynamic."""
        payload = {
            "block_hex": "0123456789ABCDEF",
            "key": "133457799BBCDFF1"
        }
        response = self.client.post('/api/comparison', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["standard_des"]["ciphertexts_are_identical"])
        self.assertFalse(data["dynamic_des"]["ciphertexts_are_identical"])


if __name__ == "__main__":
    unittest.main()
