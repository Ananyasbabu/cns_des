"""Flask Web Server for Dynamic DES Educational Visualizer."""

import os
import sys
from flask import Flask, request, jsonify, send_from_directory
from backend.des.tables import (
    IP, IP_INV, E_EXPANSION, PC1, PC2, P_PERMUTATION, LEFT_SHIFTS, S_BOXES, PARITY_BIT_POSITIONS
)
from backend.des.des_encrypt import encrypt_des
from backend.des.des_decrypt import decrypt_des
from backend.des.visualizer import STEP_PRESENTATION_EXPLANATIONS, calculate_hamming_distance
from backend.dynamic.dynamic_des import (
    encrypt_dynamic_des, decrypt_dynamic_des, compare_standard_vs_dynamic
)
from backend.utils.validation import validate_key, validate_plaintext, validate_hex_string, ValidationError

# Configure Flask to serve static files directly from the frontend directory
app = Flask(
    __name__,
    static_folder="frontend",
    template_folder="frontend",
    static_url_path=""
)


@app.route("/")
def index():
    """Serve the single-page application frontend."""
    return send_from_directory("frontend", "index.html")


@app.route("/api/status", methods=["GET"])
def get_status():
    """Return backend health check and algorithm metadata."""
    return jsonify({
        "status": "online",
        "cipher": "DES (Data Encryption Standard) + Dynamic DES",
        "block_size_bits": 64,
        "key_size_bits": 64,
        "effective_key_size_bits": 56,
        "rounds": 16,
        "sboxes_count": 8,
        "standard_reference": "NIST FIPS 46-3",
        "implementation_type": "100% Manual Internal Step Trace"
    })


@app.route("/api/tables", methods=["GET"])
def get_tables():
    """Return all standard DES permutation and substitution tables."""
    return jsonify({
        "ip": IP,
        "ip_inv": IP_INV,
        "expansion": E_EXPANSION,
        "pc1": PC1,
        "pc2": PC2,
        "p_box": P_PERMUTATION,
        "left_shifts": LEFT_SHIFTS,
        "s_boxes": S_BOXES,
        "parity_bit_positions": PARITY_BIT_POSITIONS,
        "presentation_explanations": STEP_PRESENTATION_EXPLANATIONS
    })


@app.route("/api/test-vector", methods=["GET"])
def get_test_vector():
    """Return official NIST DES test vector and verification trace."""
    pt_hex = "0123456789ABCDEF"
    key_hex = "133457799BBCDFF1"
    expected_ct_hex = "85E813540F0AB405"
    
    trace = encrypt_des(pt_hex, key_hex, input_type="hex")
    is_verified = (trace["ciphertext_hex"] == expected_ct_hex)
    
    return jsonify({
        "name": "NIST FIPS 46-3 Official Test Vector",
        "plaintext_hex": pt_hex,
        "key_hex": key_hex,
        "expected_ciphertext_hex": expected_ct_hex,
        "computed_ciphertext_hex": trace["ciphertext_hex"],
        "is_verified": is_verified,
        "trace": trace
    })


@app.route("/api/des/encrypt", methods=["POST"])
def api_encrypt():
    """Encrypt plaintext using standard manual 16-round DES."""
    data = request.get_json(force=True, silent=True) or {}
    plaintext = data.get("plaintext", "")
    key_input = data.get("key", "")
    input_type = data.get("input_type", "ascii").lower()
    
    try:
        # Validate inputs
        validated_key_hex = validate_key(key_input, input_type="hex")
        validated_pt, clean_type = validate_plaintext(plaintext, input_type=input_type)
        
        # Execute encryption with full intermediate trace
        trace = encrypt_des(validated_pt, validated_key_hex, input_type=clean_type)
        return jsonify(trace)
        
    except ValidationError as ve:
        return jsonify({"status": "error", "message": ve.message, "field": ve.field}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route("/api/des/decrypt", methods=["POST"])
def api_decrypt():
    """Decrypt ciphertext using standard manual DES with reversed subkeys (K16..K1)."""
    data = request.get_json(force=True, silent=True) or {}
    ciphertext_hex = data.get("ciphertext", "")
    key_input = data.get("key", "")
    
    try:
        validated_key_hex = validate_key(key_input, input_type="hex")
        clean_ct = validate_hex_string(ciphertext_hex, field_name="Ciphertext")
        
        if len(clean_ct) % 16 != 0:
            raise ValidationError(
                f"Ciphertext must be a multiple of 16 hex characters (64 bits). Length is {len(clean_ct)}.",
                field="ciphertext"
            )
            
        result = decrypt_des(clean_ct, validated_key_hex)
        return jsonify(result)
        
    except ValidationError as ve:
        return jsonify({"status": "error", "message": ve.message, "field": ve.field}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route("/api/dynamic/encrypt", methods=["POST"])
def api_dynamic_encrypt():
    """Encrypt data using Dynamic DES (distinct session key derived per block)."""
    data = request.get_json(force=True, silent=True) or {}
    plaintext = data.get("plaintext", "")
    master_key_input = data.get("master_key", "")
    dynamic_salt = data.get("dynamic_salt", "A5A5A5A5A5A5A5A5")
    input_type = data.get("input_type", "ascii").lower()
    
    try:
        validated_master_key = validate_key(master_key_input, input_type="hex")
        validated_salt = validate_hex_string(dynamic_salt, expected_length=16, field_name="Dynamic Salt")
        validated_pt, clean_type = validate_plaintext(plaintext, input_type=input_type)
        
        result = encrypt_dynamic_des(
            plaintext=validated_pt,
            master_key_hex=validated_master_key,
            dynamic_salt_hex=validated_salt,
            input_type=clean_type
        )
        return jsonify(result)
        
    except ValidationError as ve:
        return jsonify({"status": "error", "message": ve.message, "field": ve.field}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route("/api/dynamic/decrypt", methods=["POST"])
def api_dynamic_decrypt():
    """Decrypt Dynamic DES ciphertext."""
    data = request.get_json(force=True, silent=True) or {}
    ciphertext_hex = data.get("ciphertext", "")
    master_key_input = data.get("master_key", "")
    dynamic_salt = data.get("dynamic_salt", "A5A5A5A5A5A5A5A5")
    
    try:
        validated_master_key = validate_key(master_key_input, input_type="hex")
        validated_salt = validate_hex_string(dynamic_salt, expected_length=16, field_name="Dynamic Salt")
        clean_ct = validate_hex_string(ciphertext_hex, field_name="Ciphertext")
        
        result = decrypt_dynamic_des(
            ciphertext_hex=clean_ct,
            master_key_hex=validated_master_key,
            dynamic_salt_hex=validated_salt
        )
        return jsonify(result)
        
    except ValidationError as ve:
        return jsonify({"status": "error", "message": ve.message, "field": ve.field}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route("/api/comparison", methods=["POST"])
def api_comparison():
    """Compare Standard DES vs Dynamic DES on identical plaintext blocks."""
    data = request.get_json(force=True, silent=True) or {}
    block_hex = data.get("block_hex", "0123456789ABCDEF")
    key_hex = data.get("key", "133457799BBCDFF1")
    
    try:
        clean_block = validate_hex_string(block_hex, expected_length=16, field_name="Plaintext Block")
        clean_key = validate_key(key_hex, input_type="hex")
        result = compare_standard_vs_dynamic(clean_block, clean_key)
        return jsonify(result)
    except ValidationError as ve:
        return jsonify({"status": "error", "message": ve.message, "field": ve.field}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting Dynamic DES Visualizer on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=True)
