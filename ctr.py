import zlib
import struct
import numpy as np
import matplotlib.pyplot as plt
#from sympy import randprime
from PIL import Image
import random
import math
from helper_functions import *

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def generate_keystream(public_key, counter, length):
    e, n = public_key
    keystream = bytearray()
    while len(keystream) < length:
        counter_bytes = counter.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
        counter_encrypted = int.from_bytes(counter_bytes, byteorder='big')
        encrypted_counter = pow(counter_encrypted, e, n)
        keystream.extend(encrypted_counter.to_bytes((n.bit_length() + 7) // 8, byteorder='big'))
        counter += 1
    return bytes(keystream[:length])


def modify_png_ctr(file_path, public_key, save_path):
    data = read_png(file_path)
    new_png_data = bytearray(data[:8])
    pos = 8
    counter = 0  # Initial counter value
    encrypted_image_data = bytearray()

    while pos < len(data):
        chunk_len = struct.unpack('>I', data[pos:pos + 4])[0]
        chunk_type = data[pos + 4:pos + 8]
        chunk_data = data[pos + 8:pos + 8 + chunk_len]
        pos += 12 + chunk_len

        if chunk_type == b'IDAT':
            decompressed_data = zlib.decompress(chunk_data)
            keystream = generate_keystream(public_key, counter, len(decompressed_data))
            encrypted_data = xor_bytes(decompressed_data, keystream)
            compressed_data = zlib.compress(encrypted_data)
            chunk_data = compressed_data
            chunk_len = len(chunk_data)
            counter += 1
            encrypted_image_data.extend(encrypted_data)

        crc = zlib.crc32(chunk_type + chunk_data) & 0xffffffff
        new_png_data += struct.pack('>I', chunk_len) + chunk_type + chunk_data + struct.pack('>I', crc)

    with open(save_path, 'wb') as file:
        file.write(new_png_data)

    return encrypted_image_data


def decrypt_and_reconstruct_png_ctr(encrypted_png_path, public_key, private_key, decrypted_png_path):
    data = read_png(encrypted_png_path)
    new_png_data = bytearray(data[:8])
    pos = 8
    counter = 0  # Initial counter value

    while pos < len(data):
        chunk_len = struct.unpack('>I', data[pos:pos + 4])[0]
        chunk_type = data[pos + 4:pos + 8]
        encrypted_chunk_data = data[pos + 8:pos + 8 + chunk_len]
        pos += 12 + chunk_len

        if chunk_type == b'IDAT':
            decompressed_data = zlib.decompress(encrypted_chunk_data)
            keystream = generate_keystream(public_key, counter, len(decompressed_data))
            decrypted_data = xor_bytes(decompressed_data, keystream)
            compressed_data = zlib.compress(decrypted_data)
            chunk_data = compressed_data
            chunk_len = len(chunk_data)
            counter += 1
        else:
            chunk_data = encrypted_chunk_data

        crc = zlib.crc32(chunk_type + chunk_data) & 0xffffffff
        new_png_data += struct.pack('>I', chunk_len) + chunk_type + chunk_data + struct.pack('>I', crc)

    with open(decrypted_png_path, 'wb') as file:
        file.write(new_png_data)


public_key, private_key = generate_rsa_keys(bits=1024)
original_png_path = "example2.png"
encrypted_png_path = "encrypted_example.png"
decrypted_png_path = "decrypted_example.png"

print("Obraz oryginalny:")
display_image_from_bytes(read_png(original_png_path))

encrypted_image_data = modify_png_ctr(original_png_path, public_key, encrypted_png_path)
decrypt_and_reconstruct_png_ctr(encrypted_png_path, public_key, private_key, decrypted_png_path)

print("Obraz zaszyfrowany:")
display_encrypted_image(encrypted_image_data)

print("Obraz odszyfrowany:")
display_image_from_bytes(read_png(decrypted_png_path))
