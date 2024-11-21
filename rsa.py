import random
import math
import json

def pad(data, block_size):
    """Add PKCS#7 padding"""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data, block_size):
    """Remove PKCS#7 padding"""
    padding_length = data[-1]
    if padding_length > block_size or padding_length < 1:
        raise ValueError("Invalid padding")
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding")
    return data[:-padding_length]

def is_prime(n, k=5):
    if n < 2: return False
    if n < 4: return True
    
    # Miller-Rabin primality test
    def check(a, s, d, n):
        x = pow(a, d, n)
        if x == 1: return True
        for _ in range(s - 1):
            if x == n - 1: return True
            x = (x * x) % n
        return x == n - 1
    
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        if not check(a, s, d, n):
            return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        if n % 2 == 0:
            n += 1
        if is_prime(n):
            return n

def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi

class RSA:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        
    def generate_keypair(self, bits=1024):
        # Generate two prime numbers
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # Choose public exponent
        # e = 65537  # Commonly used value for e
        # function to generate e, not static
        e = random.randint(1, phi)
        while math.gcd(e, phi) != 1:
            e = random.randint(1, phi)
            
        # Calculate private exponent
        d = mod_inverse(e, phi)
        
        self.public_key = (n, e)
        self.private_key = (n, d)
        
        return self.public_key, self.private_key
    
    def encrypt(self, message, public_key):
        n, e = public_key
        # Convert message to number
        if isinstance(message, str):
            message_bytes = message.encode()
        else:
            message_bytes = message
        
        block_size = (n.bit_length() // 8) - 11  # Reserve space for PKCS#1 v1.5 padding
        
        encrypted_blocks = []
    
    # Process message in blocks
        for i in range(0, len(message_bytes), block_size):
            # Get block of message
            block = message_bytes[i:i + block_size]
            
            # Convert block to integer
            block_int = int.from_bytes(block, 'big')

            if block_int >= n:
                raise ValueError("Message too large for key size")
            
            # Encrypt block
            encrypted_block = pow(block_int, e, n)
            encrypted_blocks.append(str(encrypted_block))
        
        # Join all encrypted blocks with a delimiter
        return "|".join(encrypted_blocks)
    
    def decrypt(self, ciphertext, private_key):
        n, d = private_key
        try:
            # Split ciphertext into blocks
            encrypted_blocks = ciphertext.split("|")
            decrypted_parts = []
            
            # Process each block
            for block in encrypted_blocks:
                # Convert block to integer
                block_int = int(block)
                
                # Decrypt block
                decrypted_int = pow(block_int, d, n)
                
                byte_length = max((decrypted_int.bit_length() + 7) // 8, 1)
                decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')
                decrypted_parts.append(decrypted_bytes)
            
            combined_bytes = b"".join(decrypted_parts)

            try:
                return combined_bytes.decode().strip('\x00')
            except UnicodeDecodeError:
                return combined_bytes
                
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
        

    def export_key(self, key):
        """Export key as string"""
        return f"{key[0]}:{key[1]}"
    
    def import_key(self, key_str):
        """Import key from string format 'n:e' or 'n:d'"""
        if isinstance(key_str, tuple):
            return key_str
        try:
            if ':' not in str(key_str):
                raise ValueError("Invalid key format: missing separator ':'")
            n, e = str(key_str).split(':')
            return (int(n), int(e))
        except Exception as e:
            print(f"Error importing key: {e}")
            raise ValueError(f"Invalid key format: {str(e)}")
        # """Import key from string"""
        # n, e = key_str.split(':')
        # return (int(n), int(e))
    
    def encrypt_key(self, key_string, public_key):
        """Special function for encrypting key strings"""
        if isinstance(key_string, str):
            message_bytes = key_string.encode()
        else:
            message_bytes = key_string
            
        n, e = public_key
        message_int = int.from_bytes(message_bytes, 'big')
        
        if message_int >= n:
            raise ValueError("Key string too large for encryption")
            
        return str(pow(message_int, e, n))

    def decrypt_key(self, encrypted_key, private_key):
        """Special function for decrypting key strings"""
        n, d = private_key
        
        try:
            encrypted_int = int(encrypted_key)
            decrypted_int = pow(encrypted_int, d, n)
            
            byte_length = (decrypted_int.bit_length() + 7) // 8
            decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')
            
            return decrypted_bytes.decode().strip('\x00')
        except Exception as e:
            print(f"Key decryption error: {e}")
            return None
    
class ImprovedRSA:
    def encrypt(self, message, public_key):
        """
        Encrypt message using public key with proper padding
        """
        n, e = public_key
        
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message_bytes = message.encode()
        else:
            message_bytes = message
            
        # Add PKCS7 padding
        block_size = math.ceil(n.bit_length() / 8) - 11  # Reserve space for PKCS#1 v1.5 padding
        padded_data = pad(message_bytes, block_size)
        
        # Convert to integer
        message_int = int.from_bytes(padded_data, 'big')
        
        # Perform encryption
        if message_int >= n:
            raise ValueError("Message too large for the key size")
            
        ciphertext = pow(message_int, e, n)
        return ciphertext

    def decrypt(self, ciphertext, private_key):
        """
        Decrypt ciphertext using private key and handle padding
        """
        n, d = private_key
        
        # Perform decryption
        decrypted_int = pow(ciphertext, d, n)
        
        # Convert to bytes
        byte_length = math.ceil(n.bit_length() / 8)
        decrypted_bytes = decrypted_int.to_bytes(byte_length, 'big')
        
        try:
            # Remove padding
            unpadded_data = unpad(decrypted_bytes, math.ceil(n.bit_length() / 8) - 11)
            # Try to decode as string
            return unpadded_data.decode()
        except:
            # If decoding fails, return the raw decrypted bytes
            return decrypted_bytes

    def encrypt_json(self, data, public_key):
        """
        Specifically for handling JSON data
        """
        if isinstance(data, dict):
            data = json.dumps(data)
        return self.encrypt(data, public_key)

    def decrypt_json(self, ciphertext, private_key):
        """
        Decrypt and parse JSON data
        """
        decrypted = self.decrypt(ciphertext, private_key)
        return json.loads(decrypted)
    
