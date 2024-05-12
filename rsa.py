import sys
import zlib
import struct
import numpy as np
import matplotlib.pyplot as plt
from sympy import randprime, isprime
from PIL import Image
import io

# Funkcja do odczytu danych z pliku PNG
def read_png(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
    return data

# Funkcja do generowania kluczy RSA
def generate_rsa_keys(bits=1024):
    p = randprime(2**(bits//2 - 1), 2**(bits//2))  # Losowanie dużej liczby pierwszej p
    q = randprime(2**(bits//2 - 1), 2**(bits//2))  # Losowanie dużej liczby pierwszej q
    while p == q:
        q = randprime(2**(bits//2 - 1), 2**(bits//2))  # Upewniamy się, że p i q są różne
    n = p * q  # Obliczanie n = p*q, co jest modulem RSA
    phi = (p - 1) * (q - 1)  # Obliczanie funkcji Eulera phi(n)
    e = 65537  # Ustalanie publicznego eksponenta e
    d = pow(e, -1, phi)  # Obliczanie prywatnego eksponenta d
    return (e, n), (d, n)

# Funkcja do szyfrowania danych za pomocą klucza publicznego RSA
def rsa_encrypt(data, public_key):
    e, n = public_key
    max_block_size = (n.bit_length() + 7) // 8 - 1  # Maksymalny rozmiar bloku, jaki można bezpiecznie zaszyfrować
    encrypted_data = bytearray()
    for i in range(0, len(data), max_block_size):
        block = data[i:i+max_block_size]
        integer = int.from_bytes(block, 'big')
        encrypted_integer = pow(integer, e, n)  # Szyfrowanie bloku danych
        encrypted_data.extend(encrypted_integer.to_bytes((n.bit_length() + 7) // 8, 'big'))
    return bytes(encrypted_data)

# Funkcja do deszyfrowania danych za pomocą klucza prywatnego RSA
def rsa_decrypt(data, private_key):
    d, n = private_key
    block_size = (n.bit_length() + 7) // 8
    decrypted_data = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        integer = int.from_bytes(block, 'big')
        decrypted_integer = pow(integer, d, n)  # Deszyfrowanie bloku danych
        decrypted_data.extend(decrypted_integer.to_bytes(block_size - 1, 'big'))
    return bytes(decrypted_data)

# Funkcja do modyfikacji pliku PNG: szyfrowanie danych w bloku IDAT
def modify_png(file_path, public_key, save_path):
    data = read_png(file_path)
    new_png_data = bytearray(data[:8])  # Kopiowanie nagłówka PNG
    pos = 8

    encrypted_image_data = bytearray()  # Bufor na dane obrazu do wizualizacji

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
            decompressed_data = zlib.decompress(chunk_data)
            encrypted_data = rsa_encrypt(decompressed_data, public_key)
            encrypted_image_data.extend(encrypted_data)  # Zapisywanie zaszyfrowanych danych do wizualizacji
            recompressed_data = zlib.compress(encrypted_data)
            chunk_data = recompressed_data
            chunk_len = len(chunk_data)

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

# Funkcja do wyświetlania zaszyfrowanego obrazu jako obraz w skali szarości
def display_encrypted_image(data_bytes):
    length = len(data_bytes)
    side = int(np.sqrt(length / 3))  # Przybliżone wymiary obrazu dla formatu RGB
    if side * side * 3 > length:
        side -= 1

    image_array = np.frombuffer(data_bytes[:side * side * 3], dtype=np.uint8)
    image_array = image_array.reshape((side, side, 3))

    plt.imshow(image_array)
    plt.axis('off')
    plt.title("Zaszyfrowane dane obrazu")
    plt.show()

# Funkcja do deszyfrowania i odbudowy pliku PNG
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
            encrypted_data = zlib.decompress(chunk_data)
            decrypted_data = rsa_decrypt(encrypted_data, private_key)
            decompressed_data = zlib.compress(decrypted_data)
            chunk_data = decompressed_data
            chunk_len = len(chunk_data)

        new_crc = zlib.crc32(chunk_type)
        new_crc = zlib.crc32(chunk_data, new_crc)
        new_crc = struct.pack('>I', new_crc & 0xffffffff)

        new_png_data.extend(struct.pack('>I', chunk_len))
        new_png_data.extend(chunk_type)
        new_png_data.extend(chunk_data)
        new_png_data.extend(new_crc)

    with open(decrypted_png_path, 'wb') as file:
        file.write(new_png_data)

# Funkcja do wyświetlania obrazu z danych bajtowych
def display_image_from_bytes(data_bytes):
    img = Image.open(io.BytesIO(data_bytes))
    plt.imshow(img)
    plt.axis('off')
    plt.show()

# Przykład użycia:
public_key, private_key = generate_rsa_keys(bits=512)
original_png_path = "example3.png"
encrypted_png_path = "encrypted_example3.png"
decrypted_png_path = "decrypted_example3.png"

new_png_data, encrypted_image_data = modify_png(original_png_path, public_key, encrypted_png_path)
decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path)

# Wyświetlanie obrazów
print("Obraz oryginalny:")
display_image_from_bytes(read_png(original_png_path))
print("Dane obrazu zaszyfrowanego:")
display_encrypted_image(encrypted_image_data)
print("Obraz odszyfrowany:")
display_image_from_bytes(read_png(decrypted_png_path))
