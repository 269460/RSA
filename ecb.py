import zlib
import struct
import numpy as np
import matplotlib.pyplot as plt
from sympy import randprime, isprime
from PIL import Image
import io
from rsa import read_png, generate_rsa_keys, rsa_encrypt, rsa_decrypt
def ecb_encrypt_png(file_path, public_key, save_path):
    data = read_png(file_path)
    new_png_data = bytearray(data[:8])  # Kopiowanie nagłówka PNG, który pozostaje nienaruszony
    pos = 8

    while pos < len(data):
        chunk_len = struct.unpack('>I', data[pos:pos + 4])[0]
        pos += 4
        chunk_type = data[pos:pos + 4]
        pos += 4
        chunk_data = data[pos:pos + chunk_len]
        pos += chunk_len
        crc = data[pos:pos + 4]
        pos += 4

        if chunk_type == b'IDAT':
            # Dekompresja danych obrazu
            decompressed_data = zlib.decompress(chunk_data)
            # Szyfrowanie danych w trybie ECB
            encrypted_data = rsa_encrypt(decompressed_data, public_key)
            # Ponowna kompresja danych
            compressed_data = zlib.compress(encrypted_data)
            chunk_data = compressed_data
            chunk_len = len(chunk_data)

        # Obliczanie nowego CRC dla zaszyfrowanego chunku
        new_crc = zlib.crc32(chunk_type)
        new_crc = zlib.crc32(chunk_data, new_crc)
        new_crc = struct.pack('>I', new_crc & 0xffffffff)

        # Rekonstrukcja chunków PNG
        new_png_data.extend(struct.pack('>I', chunk_len))
        new_png_data.extend(chunk_type)
        new_png_data.extend(chunk_data)
        new_png_data.extend(new_crc)

    with open(save_path, 'wb') as file:
        file.write(new_png_data)

# Użycie
public_key, private_key = generate_rsa_keys(bits=1024)
original_png_path = "example.png"
ecb_encrypted_png_path = "encrypted_example.png"

ecb_encrypt_png(original_png_path, public_key, ecb_encrypted_png_path)