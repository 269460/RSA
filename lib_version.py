from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import zlib
import struct
from helper_functions import *

def rsa_encrypt(data, public_key):
    """Szyfruje dane przy użyciu publicznego klucza RSA."""
    encrypted_data = bytearray()
    max_block_size = (public_key.key_size // 8) - 2 - 2 * hashes.SHA256.digest_size
    for i in range(0, len(data), max_block_size):
        block = data[i:i + max_block_size]
        encrypted_data += public_key.encrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return bytes(encrypted_data)

def rsa_decrypt(data, private_key):
    """Deszyfruje dane przy użyciu prywatnego klucza RSA."""
    decrypted_data = bytearray()
    block_size = private_key.key_size // 8
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        decrypted_data += private_key.decrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return bytes(decrypted_data)

def modify_png(file_path, public_key, save_path, mode=0):
    """Modyfikuje plik PNG, szyfrując bloki danych IDAT."""
    with open(file_path, 'rb') as file:
        data = file.read()
    new_png_data = bytearray(data[:8])
    pos = 8
    encrypted_image_data = bytearray()
    while pos < len(data):
        chunk_len = struct.unpack('>I', data[pos:pos + 4])[0]
        chunk_type = data[pos+4:pos + 8]
        chunk_data = data[pos+8:pos + 8 + chunk_len]
        pos += 12 + chunk_len
        if chunk_type == b'IDAT':
            decompressed_data = zlib.decompress(chunk_data) if mode == 0 else chunk_data
            padded_data = add_padding(decompressed_data, (public_key.key_size // 8) - 2 - 2 * hashes.SHA256.digest_size)
            encrypted_data = rsa_encrypt(padded_data, public_key)
            encrypted_image_data.extend(encrypted_data)
            chunk_data = zlib.compress(encrypted_data) if mode == 0 else encrypted_data
            chunk_len = len(chunk_data)
        crc = zlib.crc32(chunk_type + chunk_data) & 0xffffffff
        new_png_data += struct.pack('>I', chunk_len)
        new_png_data += chunk_type
        new_png_data += chunk_data
        new_png_data += struct.pack('>I', crc)
    with open(save_path, 'wb') as file:
        file.write(new_png_data)
    return encrypted_image_data

def decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path, mode=0):
    """Odszyfrowuje i rekonstruuje plik PNG."""
    with open(encrypted_png_path, 'rb') as file:
        data = file.read()
    new_png_data = bytearray(data[:8])
    pos = 8
    while pos < len(data):
        chunk_len = struct.unpack('>I', data[pos:pos + 4])[0]
        chunk_type = data[pos+4:pos + 8]
        encrypted_chunk_data = data[pos+8:pos + 8 + chunk_len]
        pos += 12 + chunk_len
        if chunk_type == b'IDAT':
            encrypted_data = zlib.decompress(encrypted_chunk_data) if mode == 0 else encrypted_chunk_data
            decrypted_data = rsa_decrypt(encrypted_data, private_key)
            padded_decrypted_data = remove_padding(decrypted_data)
            chunk_data = zlib.compress(padded_decrypted_data) if mode == 0 else padded_decrypted_data
            chunk_len = len(chunk_data)
        else:
            chunk_data = encrypted_chunk_data
        crc = zlib.crc32(chunk_type + chunk_data) & 0xffffffff
        new_png_data += struct.pack('>I', chunk_len)
        new_png_data += chunk_type
        new_png_data += chunk_data
        new_png_data += struct.pack('>I', crc)
    with open(decrypted_png_path, 'wb') as file:
        file.write(new_png_data)

# Generowanie kluczy RSA
public_key, private_key = generate_rsa_keys()
original_png_path = 'example2.png'
encrypted_png_path = 'enc_example.png'
decrypted_png_path = 'dec_example.png'

# Wyświetlanie oryginalnego obrazu
print("Obraz oryginalny:")
display_image_from_bytes(read_png(original_png_path))

for mode in range(2):
    # Szyfrowanie pliku PNG
    print(f"Szyfrowanie pliku PNG z mode={mode}...")
    encrypted_image_data = modify_png(original_png_path, public_key, encrypted_png_path, mode)

    # Deszyfrowanie pliku PNG
    print(f"Deszyfrowanie pliku PNG z mode={mode}...")
    decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path, mode)

    # Wyświetlanie zaszyfrowanego obrazu
    print(f"Wyświetlanie zaszyfrowanego obrazu z mode={mode}:")
    display_encrypted_image(encrypted_image_data)

    # Wyświetlanie odszyfrowanego obrazu
    print(f"Wyświetlanie odszyfrowanego obrazu z mode={mode}:")
    display_image_from_bytes(read_png(decrypted_png_path))
