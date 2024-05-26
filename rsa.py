import zlib
import struct
import numpy as np
import matplotlib.pyplot as plt
from sympy import randprime, isprime
from PIL import Image
import io
import random
import math

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
    while True:
        e = random.randint(2, phi-1)
        if math.gcd(e,phi)==1:
            break
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def add_padding(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    padded_data = data + bytes([padding_length] * padding_length)
    return padded_data

def remove_padding(data):
    padding_length = data[-1]
    return data[:-padding_length]

def rsa_encrypt(data, public_key):
    e, n = public_key
    max_block_size = (n.bit_length() + 7) // 8 - 1
    encrypted_data = bytearray()
    for i in range(0, len(data), max_block_size):
        block = data[i:i+max_block_size]
        integer = int.from_bytes(block, 'big')
        encrypted_integer = pow(integer, e, n)
        encrypted_data.extend(encrypted_integer.to_bytes((n.bit_length() + 7) // 8, 'big'))
    return bytes(encrypted_data)

def rsa_decrypt(data, private_key):
    d, n = private_key
    block_size = (n.bit_length() + 7) // 8
    decrypted_data = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        integer = int.from_bytes(block, 'big')
        decrypted_integer = pow(integer, d, n)
        decrypted_data.extend(decrypted_integer.to_bytes(block_size - 1, 'big'))
    return bytes(decrypted_data)

def modify_png(file_path, public_key, save_path, mode=0):
    # mode = 0 decompression->enryption->compression
    # mode = 1 encryption
    e, n = public_key  # Rozpakowuj klucz publiczny do e i n
    data = read_png(file_path)
    new_png_data = bytearray(data[:8])
    pos = 8
    encrypted_image_data = bytearray()

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
            try:
                if mode==0:
                    decompressed_data = zlib.decompress(chunk_data)
                elif mode==1:
                    decompressed_data=chunk_data
                padded_data = add_padding(decompressed_data, (n.bit_length() + 7) // 8 - 1)
                encrypted_data = rsa_encrypt(padded_data, public_key)
                encrypted_image_data.extend(encrypted_data)
                if mode==0:
                    recompressed_data = zlib.compress(encrypted_data)
                elif mode==1:
                    recompressed_data = encrypted_data
                chunk_data = recompressed_data
                chunk_len = len(chunk_data)
            except zlib.error as e:
                print("Error decompressing data: ", str(e))
                continue  # Przechodź do kolejnego chunka

        new_crc = zlib.crc32(chunk_type)
        new_crc = zlib.crc32(chunk_data, new_crc)
        new_crc = struct.pack('>I', new_crc & 0xffffffff)

        new_png_data.extend(struct.pack('>I', chunk_len))
        new_png_data.extend(chunk_type)
        new_png_data.extend(chunk_data)
        new_png_data.extend(new_crc)

    with open(save_path, 'wb') as file:
        file.write(new_png_data)

    return new_png_data, encrypted_image_data

def decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path, mode=0):
    # mode = 0 decompression->decryption->compression
    # mode = 1 decryption
    data = read_png(encrypted_png_path)
    new_png_data = bytearray(data[:8])  # Kopiowanie nagłówka PNG
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
            try:
                if mode==0:
                    encrypted_data = zlib.decompress(chunk_data)
                elif mode==1:
                    encrypted_data=chunk_data
                # Deszyfrowanie danych
                decrypted_data = rsa_decrypt(encrypted_data, private_key)
                # Usunięcie paddingu
                padded_decrypted_data = remove_padding(decrypted_data)
                # Kompresja danych po usunięciu paddingu
                if mode==0:
                    decompressed_data = zlib.compress(padded_decrypted_data)
                elif mode==1:
                    decompressed_data = padded_decrypted_data
                chunk_data = decompressed_data
                chunk_len = len(chunk_data)
            except zlib.error as e:
                print(f"Błąd zlib przy próbie dekompresji: {str(e)}")
                continue  # Przechodź do kolejnego chunka, pomijając uszkodzone

        # Obliczanie nowego CRC dla zmodyfikowanego chunku
        new_crc = zlib.crc32(chunk_type)
        new_crc = zlib.crc32(chunk_data, new_crc)
        new_crc = struct.pack('>I', new_crc & 0xffffffff)

        # Rekonstrukcja chunków PNG
        new_png_data.extend(struct.pack('>I', chunk_len))
        new_png_data.extend(chunk_type)
        new_png_data.extend(chunk_data)
        new_png_data.extend(new_crc)

    with open(decrypted_png_path, 'wb') as file:
        file.write(new_png_data)

def display_image_from_bytes(data_bytes):
    img = Image.open(io.BytesIO(data_bytes))
    plt.imshow(img)
    plt.axis('off')
    plt.show()

def display_encrypted_image(data_bytes):
    if len(data_bytes) == 0:
        print("Brak danych do wyświetlenia. Możliwe, że zaszyfrowane dane są puste lub uszkodzone.")
        return

    try:
        length = len(data_bytes)
        side = int(np.sqrt(length / 3))  # Estymowanie wymiarów obrazu dla RGB
        if side * side * 3 > length:
            side -= 1

        image_array = np.frombuffer(data_bytes[:side * side * 3], dtype=np.uint8).reshape((side, side, 3))
        plt.imshow(image_array)
        plt.axis('off')
        plt.title("Zaszyfrowane dane obrazu")
        plt.show()
    except Exception as e:
        print(f"Wystąpił błąd podczas wyświetlania obrazu: {str(e)}")

public_key, private_key = generate_rsa_keys(bits=1024)
original_png_path = "example9.png"
encrypted_png_path = "encrypted_example.png"
decrypted_png_path = "decrypted_example.png"

print("Obraz oryginalny:")
display_image_from_bytes(read_png(original_png_path))

for mode in range(2):
    new_png_data, encrypted_image_data = modify_png(original_png_path, public_key, encrypted_png_path, mode)
    decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path, mode)

    print("Dane obrazu zaszyfrowanego:")
    display_encrypted_image(encrypted_image_data)
    print("Obraz odszyfrowany:")
    display_image_from_bytes(read_png(decrypted_png_path))
