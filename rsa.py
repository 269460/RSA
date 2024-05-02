import sys
import zlib
import struct
from sympy import randprime, isprime

def read_png(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
    return data

def generate_rsa_keys(bits=1024):
    p = randprime(2**(bits//2 - 1), 2**(bits//2))
    q = randprime(2**(bits//2 - 1), 2**(bits//2))
    while p == q:
        q = randprime(2**(bits//2 - 1), 2**(bits//2))
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def rsa_encrypt(data, public_key):
    e, n = public_key
    max_block_size = (n.bit_length() + 7) // 8 - 1  # Maksymalny rozmiar bloku danych, który może być bezpiecznie zaszyfrowany
    encrypted_data = bytearray()
    for i in range(0, len(data), max_block_size):
        block = data[i:i+max_block_size]
        integer = int.from_bytes(block, 'big')
        encrypted_integer = pow(integer, e, n)
        # Alokacja wystarczającej ilości bajtów dla zaszyfrowanego wyniku
        encrypted_data.extend(encrypted_integer.to_bytes((n.bit_length() + 7) // 8, 'big'))
    return bytes(encrypted_data)

def rsa_decrypt(data, private_key):
    d, n = private_key
    block_size = (n.bit_length() // 8)
    decrypted_data = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        integer = int.from_bytes(block, 'big')
        decrypted_integer = pow(integer, d, n)
        decrypted_data.extend(decrypted_integer.to_bytes(block_size - 1, 'big'))
    return bytes(decrypted_data)

def modify_png(file_path, public_key, save_path):
    data = read_png(file_path)
    new_png_data = bytearray(data[:8])  # Kopiowanie nagłówka PNG
    pos = 8

    while pos < len(data):
        chunk_len = struct.unpack('>I', data[pos:pos+4])[0]
        pos += 4
        chunk_type = data[pos:pos+4]
        pos += 4
        chunk_data = data[pos:pos+chunk_len]
        pos += chunk_len
        crc = data[pos:pos+4]
        pos += 4

        if chunk_type == b'IDAT':
            # Dekompresja danych
            decompressed_data = zlib.decompress(chunk_data)
            # Szyfrowanie danych
            encrypted_data = rsa_encrypt(decompressed_data, public_key)
            # Kompresja zaszyfrowanych danych
            chunk_data = zlib.compress(encrypted_data)
            chunk_len = len(chunk_data)

        # Obliczanie nowego CRC
        new_crc = zlib.crc32(chunk_type)
        new_crc = zlib.crc32(chunk_data, new_crc)
        new_crc = struct.pack('>I', new_crc & 0xffffffff)
        new_png_data.extend(struct.pack('>I', chunk_len))
        new_png_data.extend(chunk_type)
        new_png_data.extend(chunk_data)
        new_png_data.extend(new_crc)

    with open(save_path, 'wb') as file:
        file.write(new_png_data)

def decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path):
    data = read_png(encrypted_png_path)
    new_png_data = bytearray(data[:8])  # Kopiowanie nagłówka PNG
    pos = 8

    while pos < len(data):
        chunk_len = struct.unpack('>I', data[pos:pos+4])[0]
        pos += 4
        chunk_type = data[pos:pos+4]
        pos += 4
        chunk_data = data[pos:pos+chunk_len]
        pos += chunk_len
        crc = data[pos:pos+4]
        pos += 4

        if chunk_type == b'IDAT':
            # Dekompresja zaszyfrowanych danych
            decompressed_data = zlib.decompress(chunk_data)
            # Deszyfrowanie danych
            decrypted_data = rsa_decrypt(decompressed_data, private_key)
            # Kompresja odszyfrowanych danych
            chunk_data = zlib.compress(decrypted_data)
            chunk_len = len(chunk_data)

        # Obliczanie nowego CRC
        new_crc = zlib.crc32(chunk_type)
        new_crc = zlib.crc32(chunk_data, new_crc)
        new_crc = struct.pack('>I', new_crc & 0xffffffff)
        new_png_data.extend(struct.pack('>I', chunk_len))
        new_png_data.extend(chunk_type)
        new_png_data.extend(chunk_data)
        new_png_data.extend(new_crc)

    with open(decrypted_png_path, 'wb') as file:
        file.write(new_png_data)

# Użycie:
public_key, private_key = generate_rsa_keys(bits=512)
original_png_path = "example3.png"
encrypted_png_path = "encrypted_example3.png"
decrypted_png_path = "decrypted_example3.png"

modify_png(original_png_path, public_key, encrypted_png_path)
decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path)
