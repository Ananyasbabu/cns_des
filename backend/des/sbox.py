"""DES Substitution Box (S-Box) processing and detailed educational inspection."""

from typing import List, Dict, Any, Tuple
from backend.des.tables import S_BOXES


def substitute_single_box(box_index: int, six_bits: str) -> Dict[str, Any]:
    """Perform substitution on a single 6-bit block using S-Box (1 to 8).
    
    Formula:
    Row = bit 1 (MSB) and bit 6 (LSB) -> 2 bits (0 to 3)
    Column = bits 2, 3, 4, 5 (middle 4 bits) -> 4 bits (0 to 15)
    Output = 4 bits from S_BOXES[box_index][row][column]
    """
    clean_bits = six_bits.replace(" ", "")
    if len(clean_bits) != 6:
        raise ValueError(f"S-box requires exactly 6 input bits, got {len(clean_bits)}")
        
    b1 = clean_bits[0]
    b6 = clean_bits[5]
    row_bin = b1 + b6
    row = int(row_bin, 2)
    
    col_bin = clean_bits[1:5]
    col = int(col_bin, 2)
    
    val = S_BOXES[box_index][row][col]
    out_bin = bin(val)[2:].zfill(4)
    out_hex = hex(val)[2:].upper()
    
    return {
        "box_num": box_index + 1,
        "input_bits": clean_bits,
        "row_bits": row_bin,
        "row": row,
        "col_bits": col_bin,
        "col": col,
        "value": val,
        "output_bits": out_bin,
        "output_hex": out_hex,
        "matrix": S_BOXES[box_index]
    }


def sbox_substitution(bits_48: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Run all 8 S-Boxes on a 48-bit string and return combined 32 bits and full trace."""
    clean_48 = bits_48.replace(" ", "")
    if len(clean_48) != 48:
        raise ValueError(f"S-box substitution input must be 48 bits, got {len(clean_48)}")
        
    box_results = []
    output_32_list = []
    
    for i in range(8):
        six_bit_block = clean_48[i * 6 : (i + 1) * 6]
        res = substitute_single_box(i, six_bit_block)
        box_results.append(res)
        output_32_list.append(res["output_bits"])
        
    output_32 = "".join(output_32_list)
    return output_32, box_results


# Type alias helper
Tuple_Output = tuple[str, List[Dict[str, Any]]]
