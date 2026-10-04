# Dynamic DES — Step-by-Step Educational Cryptography Visualizer

> **Academic Notice**: DES is historically foundational in computer security and cryptography education, but is **not** recommended as a modern production encryption algorithm due to its 56-bit effective key size (vulnerable to brute-force attacks). This project is an **educational demonstration** of DES internal operations and dynamic key-changing mechanisms designed for Cryptography & Network Security (CNS) coursework, viva presentations, and laboratory study.

---

## 1. What is DES?

The **Data Encryption Standard (DES)** is a symmetric-key block cipher published by the National Bureau of Standards (now NIST) in 1977 as FIPS PUB 46. Developed by IBM, DES encrypts data in 64-bit blocks using a 56-bit effective key through a 16-round **Feistel network**.

---

## 2. Why Study DES?

Although replaced by AES (Advanced Encryption Standard) for commercial encryption, DES is the **quintessential pedagogical cipher** taught in university computer science curricula:
- It introduces the **Feistel cipher architecture**, guaranteeing mathematical reversibility.
- It demonstrates Claude Shannon's foundational principles of **Confusion** (non-linear S-boxes) and **Diffusion** (expansion and P-boxes).
- It highlights key management concepts such as **parity check bits**, circular left shifts, and subkey compression.
- It provides a historical case study for cryptographic cryptanalysis (differential and linear cryptanalysis).

---

## 3. High-Level Architecture

```text
                                USER INPUT
                                    │
                                    ▼
                          Plaintext + 64-bit Key
                                    │
                  ┌─────────────────┴─────────────────┐
                  ▼                                   ▼
        ┌───────────────────┐               ┌───────────────────┐
        │  Plaintext (64b)  │               │   64-bit Key      │
        └─────────┬─────────┘               └─────────┬─────────┘
                  │                                   │
                  ▼                                   ▼
        ┌───────────────────┐               ┌───────────────────┐
        │Initial Permutation│               │ PC-1 Permutation  │
        │       (IP)        │               │(Strips 8 parities)│
        └─────────┬─────────┘               └─────────┬─────────┘
                  │                                   │
                  ▼                                   ▼
        ┌───────────────────┐               ┌───────────────────┐
        │ L0 (32b) | R0 (32b)               │ C0 (28b) | D0 (28b)
        └─────────┬─────────┘               └─────────┬─────────┘
                  │                                   │
                  │        Round Subkeys K1..K16      │
                  │◄──────────────────────────────────┘
                  │    (Circular Shifts + PC-2)
                  ▼
        ┌───────────────────────────────────────────────────────┐
        │             16 FEISTEL ENCRYPTION ROUNDS              │
        │                                                       │
        │  Li = R(i-1)                                          │
        │  Ri = L(i-1) ⊕ F(R(i-1), Ki)                          │
        │                                                       │
        │  Where F(R, K) = P-Box(S-Boxes(E(R) ⊕ Ki))            │
        └───────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
        ┌───────────────────────────────────────────────────────┐
        │              32-bit Swap: R16 || L16                  │
        └───────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
        ┌───────────────────────────────────────────────────────┐
        │         Inverse Initial Permutation (IP⁻¹)            │
        └───────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
                        64-Bit Final Ciphertext
```

---

## 4. The 16-Round Feistel Network

DES is based on Horst Feistel's symmetric structure. The 64-bit block is split into:
$$L_0 \in \{0, 1\}^{32}, \quad R_0 \in \{0, 1\}^{32}$$

For rounds $i = 1, 2, \dots, 16$:
$$L_i = R_{i-1}$$
$$R_i = L_{i-1} \oplus F(R_{i-1}, K_i)$$

After Round 16, a pre-output swap produces $R_{16} \parallel L_{16}$, followed by $\text{IP}^{-1}$.

### Why Feistel is Reversible
The Feistel structure can be inverted without computing an inverse of the round function $F$:
$$R_{i-1} = L_i$$
$$L_{i-1} = R_i \oplus F(L_i, K_i)$$
Decryption uses the **exact same circuit/code**, simply supplying subkeys in reverse order ($K_{16}, K_{15}, \dots, K_1$).

---

## 5. Round Function $F(R_{i-1}, K_i)$ Breakdown

The round function consists of 4 strict steps:

1. **Expansion Permutation ($E$)**: Expands 32-bit $R_{i-1}$ to 48 bits by duplicating 16 edge bits according to standard table $E$.
2. **Key XOR**: 48-bit expanded right half is XORed with the 48-bit subkey:
   $$A = E(R_{i-1}) \oplus K_i$$
3. **S-Box Substitution**: 48-bit stream is partitioned into eight 6-bit groups $B_1, \dots, B_8$:
   - For 6-bit block $b_1 b_2 b_3 b_4 b_5 b_6$:
     - $\text{Row} = (b_1 b_6)_2 \in [0..3]$
     - $\text{Column} = (b_2 b_3 b_4 b_5)_2 \in [0..15]$
     - $\text{Output} = S_k[\text{Row}][\text{Column}] \in [0..15]$ (4 bits)
   - 8 boxes $\times$ 4 bits = **32 bits output**.
4. **Straight P-Box Permutation ($P$)**: Transposes the 32 bits from the S-boxes to distribute their influence across different S-boxes in subsequent rounds.

---

## 6. Key Generation & Key Schedule

1. **Parity Inspection**: Bits 8, 16, 24, 32, 40, 48, 56, 64 are parity bits.
2. **PC-1 (Permuted Choice 1)**: Discards the 8 parity bits and transposes the remaining 56 bits into two 28-bit halves: $C_0$ and $D_0$.
3. **Left Circular Shifts**: In each round $i$, $C$ and $D$ are circularly shifted left:
   - Rounds 1, 2, 9, 16: **1 bit**
   - Rounds 3–8, 10–15: **2 bits**
   - Total shifts: $4 \times 1 + 12 \times 2 = 28$ bits (full cycle).
4. **PC-2 (Permuted Choice 2)**: Compresses the 56 shifted bits ($C_i \parallel D_i$) into a **48-bit subkey** $K_i$.

---

## 7. Dynamic DES Concept & Mechanism

### The Standard DES Electronic Codebook (ECB) Vulnerability
In standard DES (ECB mode), encrypting multiple blocks with a single static key has a critical flaw:
$$\text{If } \text{Block}_1 == \text{Block}_2 \implies \text{Cipher}_1 == \text{Cipher}_2$$
An eavesdropper can perform frequency analysis and replay attacks because identical plaintexts leak identical ciphertexts.

### The Dynamic Key-Changing Solution
In **Dynamic DES**, the algorithm remains 100% compliant with standard DES rounds, but the encryption key is dynamically derived for every block:
$$K^{(i)} = \text{DeriveKey}(K_{\text{master}}, \text{BlockIndex } i, \text{Salt})$$

- **Block Index Injection**: A deterministic dispersion formula ($i \times \phi$) alters the key material.
- **Dynamic Rotation**: The key bits undergo block-dependent rotation.
- **Parity Correction**: Parity bits are re-aligned to maintain valid DES key requirements.
- **Result**: Identical plaintext blocks produce completely distinct, pseudorandom ciphertext blocks with an avalanche effect $\approx 50\%$, eliminating the ECB repetition flaw.

---

## 8. Technology Stack

- **Backend**: Python 3.13 / Flask (Modular architecture, zero library encryption wrappers).
- **Frontend**: HTML5, Modern CSS (Custom properties, dark/light themes), Vanilla JavaScript (No React dependency).
- **Testing**: Python `unittest` framework (24 automated tests including standard NIST test vectors).

---

## 9. Project Directory Structure

```text
dynamic-des-visualizer/
├── app.py                     # Flask entry point and REST API
├── requirements.txt           # Minimal dependencies (Flask, pytest)
├── README.md                  # Comprehensive educational documentation
│
├── backend/
│   ├── __init__.py
│   ├── des/
│   │   ├── __init__.py
│   │   ├── tables.py          # NIST FIPS 46-3 constants (IP, IP_INV, E, PC1, PC2, P, S-Boxes)
│   │   ├── permutation.py     # Permutation, rotation, and bitwise XOR
│   │   ├── key_schedule.py    # PC-1, 28-bit C/D split, shifts, PC-2, 16 subkeys
│   │   ├── sbox.py            # S-Box row (b1,b6) and col (b2..b5) extraction & substitution
│   │   ├── round_function.py  # Feistel F: E -> XOR Ki -> S-Boxes -> P-Box
│   │   ├── des_encrypt.py     # 16-round manual encryption recording full trace JSON
│   │   ├── des_decrypt.py     # Decryption using reverse subkeys (K16..K1)
│   │   └── visualizer.py      # Trace formatting and educational annotations
│   │
│   ├── dynamic/
│   │   ├── __init__.py
│   │   └── dynamic_des.py     # Block-dependent dynamic key derivation & comparison
│   │
│   └── utils/
│       ├── __init__.py
│       ├── binary_utils.py    # Hex/Binary/ASCII conversions, PKCS#7, parity checks
│       └── validation.py      # Input validation & friendly error handling
│
├── frontend/
│   ├── index.html             # Multi-tab modern UI (Dashboard, Key Gen, DES Rounds, S-Boxes, etc.)
│   ├── style.css              # Responsive dark/light theme with cyber/academic styling
│   └── script.js              # Step player, interactive tables, S-box matrices, comparison
│
└── tests/
    ├── test_des.py            # NIST test vector & round-by-round assertions
    ├── test_key_schedule.py   # Parity bits, PC-1, shifts, PC-2 assertions
    ├── test_sbox.py           # S-Box row/col indexing & table value assertions
    ├── test_dynamic_des.py    # Dynamic key generation & ECB elimination assertions
    └── test_flask_api.py      # Flask REST API endpoints & frontend serving assertions
```

---

## 10. How to Install & Run

### Prerequisites
- Python 3.10+ (Tested on Python 3.13)

### Installation
Clone or navigate to the project directory:
```bash
cd "cns project 1"
```

Activate or create virtual environment:
```powershell
python -m venv venv
.\venv\Scripts\activate
```

Install requirements:
```powershell
pip install -r requirements.txt
```

### Running Automated Tests
Run the comprehensive 24-test suite:
```powershell
py -3 -m unittest discover -s tests -p "test_*.py" -v
```

### Starting the Web Application
```powershell
py -3 app.py
```
Open your browser at:
```text
http://127.0.0.1:5000
```

---

## 11. Official Standard DES Test Vector

| Field | Value |
| :--- | :--- |
| **Plaintext (Hex)** | `0123456789ABCDEF` |
| **DES Key (Hex)** | `133457799BBCDFF1` |
| **Expected Ciphertext (Hex)** | `85E813540F0AB405` |

The manually implemented DES engine in `backend/des/des_encrypt.py` computes exactly:
```text
85E813540F0AB405
```
Verified across test suites and integrated directly into the UI via the **"Load Test Vector"** button.

---

## 12. College Presentation & Viva Cheat Sheet

### When Presenting to the Professor:
1. **Explain the Motivation**:
   - "DES is the historic foundation of block ciphers and Feistel networks."
   - "Our project implements every internal bit-level operation manually so that every intermediate state is fully transparent and inspectable."
2. **Demonstrate the Standard Vector**:
   - Click **"Load Test Vector"** $\to$ click **"Start Encryption"**.
   - Point out that `0123456789ABCDEF` with key `133457799BBCDFF1` produces NIST standard ciphertext `85E813540F0AB405`.
3. **Walk Through the Tabs**:
   - **Key Generation**: Show the 8 parity bits discarded by PC-1, the 28-bit halves $C_0$ and $D_0$, and the shift schedule ($1, 1, 2, 2 \dots$). Click any key row to open the Subkey Inspector.
   - **DES Encryption**: Show the 64-bit Initial Permutation (IP), $L_0/R_0$, and the 16 rounds summary.
   - **Round Details**: Select any round (e.g., Round 1) to show Expansion $E$, 48-bit XOR with $K_i$, S-box substitution, and P-box diffusion.
   - **S-Box Analysis**: Show how a 6-bit input splits into Row $(b_1 b_6)$ and Column $(b_2..b_5)$ and highlights the exact matrix cell.
   - **Dynamic DES**: Demonstrate how Dynamic Key Derivation breaks ECB repetition for identical plaintext blocks.
   - **Decryption**: Click "Show Decryption Steps" to prove that applying reversed subkeys ($K_{16} \to K_1$) recovers the original message without changing the round function.
