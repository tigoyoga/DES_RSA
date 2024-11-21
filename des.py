import random
import binascii

IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

S_BOX = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
	],
	# S4
	[
	    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
	],
	# S5
	[
	    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
	],
	# S6
	[
	    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
	],
	# S7
	[
	    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
	],
	# S8
	[
	    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
	]
]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

SHIFT_TABLE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def generate_random_des_key():
    """Generate random 64-bit (16 hex characters) DES key"""
    key = ''
    hex_chars = '0123456789ABCDEF'
    for _ in range(16):
        key += random.choice(hex_chars)
    return key

def f_function(right_half, subkey):
    expanded = permute(right_half, E)
    xored = xor(expanded, subkey)
    substituted = s_box_substitution(xored)
    permuted = permute(substituted, P)

    return permuted

def pad(text):
    pad_len = 8 - (len(text) % 8)
    padding = chr(pad_len) * pad_len
    return text + padding

def unpad(text):
    pad_len = ord(text[-1])
    if pad_len > 8 or pad_len < 1:
        return text  # Invalid padding
    for i in range(1, pad_len + 1):
        if ord(text[-i]) != pad_len:
            return text  # Invalid padding
    return text[:-pad_len]

def generate_key():
    return ''.join(random.choice('0123456789ABCDEF') for _ in range(16))

def hex_key_to_binary(hex_key):
    binary = bin(int(hex_key, 16))[2:].zfill(80)
    return binary[:64]

def bin_to_hex(binary):
    return hex(int(binary, 2))[2:]

def permute(block, table):
    return ''.join(block[i-1] for i in table)

def s_box_substitution(expanded_block):
    output = ""
    for i in range(8):
        block = expanded_block[i*6:(i+1)*6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        output += format(S_BOX[i][row][col], '04b')
    return output

def des_round(left_half, right_half, subkey):
    new_left = right_half
    f_result = f_function(right_half, subkey)
    new_right = xor(left_half, f_result)
    return new_left, new_right

def xor(a, b):
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))

def left_shift(key, n):
    return key[n:] + key[:n]

def string_to_bit_array(text):
    return ''.join(format(ord(char), '08b') for char in text)

def bit_array_to_string(bits):
    return ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))

def generate_subkeys(key):
    key = permute(key, PC1)
    left = key[:28]
    right = key[28:]
    subkeys = []

    for i in range(16):
        left = left_shift(left, SHIFT_TABLE[i])
        right = left_shift(right, SHIFT_TABLE[i])
        subkey = permute(left + right, PC2)
        subkeys.append(subkey)

    return subkeys

def des_encrypt(plaintext, hex_key):
    original_plaintext = plaintext
    padded_plaintext = pad(plaintext)
    binary_key = hex_key_to_binary(hex_key)
    
    # print original message and key
    print("\nOriginal Message:", original_plaintext)
    print("Hexadecimal Key (64-bit):", hex_key)
    
    plaintext_bits = string_to_bit_array(padded_plaintext)
    
    ciphertext_bits = ""
    for i in range(0, len(plaintext_bits), 64):
        block = plaintext_bits[i:i+64]
        block = permute(block, IP)
        left_half = block[:32]
        right_half = block[32:]
        
        subkeys = generate_subkeys(binary_key)
        
        for j in range(16):
            left_half, right_half = des_round(left_half, right_half, subkeys[j])
        
        block = permute(right_half + left_half, IP_INV)
        ciphertext_bits += block
    
    ciphertext = bit_array_to_string(ciphertext_bits)

    return ciphertext

def des_decrypt(ciphertext, hex_key):
    binary_key = hex_key_to_binary(hex_key)
    
    print("\nCipher Message:", ciphertext)
    print("Hexadecimal Key (64-bit):", hex_key)
    
    ciphertext_bits = string_to_bit_array(ciphertext)
    
    plaintext_bits = ""
    for i in range(0, len(ciphertext_bits), 64):
        block = ciphertext_bits[i:i+64]
        block = permute(block, IP)
        left_half = block[:32]
        right_half = block[32:]
        
        subkeys = generate_subkeys(binary_key)
        subkeys.reverse()
        
        for j in range(16):
            left_half, right_half = des_round(left_half, right_half, subkeys[j])
        
        block = permute(right_half + left_half, IP_INV)
        plaintext_bits += block
    
    decrypted_text = bit_array_to_string(plaintext_bits)
    unpadded_text = unpad(decrypted_text)

    return unpadded_text
