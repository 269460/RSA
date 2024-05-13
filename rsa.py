import zlib
import struct
import numpy as np
import matplotlib.pyplot as plt
from sympy import randprime, isprime
from PIL import Image
import io

def read_png(file_path):
    """ Odczyt danych z pliku PNG. """
    with open(file_path, 'rb') as file:
        data = file.read()
    return data

def generate_rsa_keys(bits=1024):
    """ Generowanie par kluczy RSA. """
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
    """ Szyfrowanie danych używając klucza publicznego RSA. """
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
    """ Deszyfrowanie danych używając klucza prywatnego RSA. """
    d, n = private_key
    block_size = (n.bit_length() + 7) // 8
    decrypted_data = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        integer = int.from_bytes(block, 'big')
        decrypted_integer = pow(integer, d, n)
        decrypted_data.extend(decrypted_integer.to_bytes(block_size - 1, 'big'))
    return bytes(decrypted_data)

def modify_png(file_path, public_key, save_path):
    """ Szyfrowanie danych w bloku IDAT obrazu PNG. """
    data = read_png(file_path)
    new_png_data = bytearray(data[:8])  # Kopiowanie nagłówka PNG, który pozostaje nienaruszony
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

def display_image_from_bytes(data_bytes):
    """ Wyświetlanie obrazu z danych bajtowych. """
    img = Image.open(io.BytesIO(data_bytes))
    plt.imshow(img)
    plt.axis('off')
    plt.show()

def display_encrypted_image(data_bytes):
    """ Wyświetlanie zaszyfrowanego obrazu jako obraz w skali szarości. """
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

def decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path):
    """ Deszyfrowanie i odbudowywanie pliku PNG. """
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

# Przykład użycia:
public_key, private_key = generate_rsa_keys(bits=512)
original_png_path = "example6.png"
encrypted_png_path = "encrypted_example.png"
decrypted_png_path = "decrypted_example.png"

new_png_data, encrypted_image_data = modify_png(original_png_path, public_key, encrypted_png_path)
decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path)

# Wyświetlanie obrazów
print("Obraz oryginalny:")
display_image_from_bytes(read_png(original_png_path))
print("Dane obrazu zaszyfrowanego:")
display_encrypted_image(encrypted_image_data)
print("Obraz odszyfrowany:")
display_image_from_bytes(read_png(decrypted_png_path))
