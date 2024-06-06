from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zlib
import struct
from PIL import Image
import io
import matplotlib.pyplot as plt
import numpy as np

def read_png(file_path):
    """Czyta plik PNG i zwraca jego zawartość jako bajty."""
    with open(file_path, 'rb') as file:
        data = file.read()
    return data

def generate_rsa_keys():
    """Generuje i zwraca publiczny i prywatny klucz RSA."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def rsa_encrypt(data, public_key):
    """Szyfruje dane przy użyciu publicznego klucza RSA."""
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_data = bytearray()
    block_size = cipher._key.size_in_bytes() - 2 * cipher._hashObj.digest_size - 2
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        encrypted_data += cipher.encrypt(block)
    return bytes(encrypted_data)

def rsa_decrypt(data, private_key):
    """Deszyfruje dane przy użyciu prywatnego klucza RSA."""
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_data = bytearray()
    block_size = cipher._key.size_in_bytes()
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        decrypted_data += cipher.decrypt(block)
    return bytes(decrypted_data)

def modify_png(file_path, public_key, save_path):
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
            decompressed_data = zlib.decompress(chunk_data)
            encrypted_data = rsa_encrypt(decompressed_data, public_key)
            compressed_data = zlib.compress(encrypted_data)
            chunk_data = compressed_data
            chunk_len = len(chunk_data)
            encrypted_image_data.extend(encrypted_data)
        crc = zlib.crc32(chunk_type + chunk_data) & 0xffffffff
        new_png_data += struct.pack('>I', chunk_len)
        new_png_data += chunk_type
        new_png_data += chunk_data
        new_png_data += struct.pack('>I', crc)
    with open(save_path, 'wb') as file:
        file.write(new_png_data)
    return encrypted_image_data

def decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path):
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
            try:
                encrypted_data = zlib.decompress(encrypted_chunk_data)
                decrypted_data = rsa_decrypt(encrypted_data, private_key)
                chunk_data = zlib.compress(decrypted_data)
                chunk_len = len(chunk_data)
            except Exception as e:
                print(f"Błąd przy dekompresji lub deszyfrowaniu chunku: {e}")
                chunk_data = encrypted_chunk_data
        else:
            chunk_data = encrypted_chunk_data
        crc = zlib.crc32(chunk_type + chunk_data) & 0xffffffff
        new_png_data += struct.pack('>I', chunk_len)
        new_png_data += chunk_type
        new_png_data += chunk_data
        new_png_data += struct.pack('>I', crc)
    with open(decrypted_png_path, 'wb') as file:
        file.write(new_png_data)

def display_image_from_bytes(data_bytes):
    """Wyświetla obraz z bajtów danych."""
    img = Image.open(io.BytesIO(data_bytes))
    plt.imshow(img)
    plt.axis('off')
    plt.show()

def display_encrypted_image(encrypted_image_data):
    """Wyświetla zaszyfrowany obraz jako dane RGB."""
    if len(encrypted_image_data) == 0:
        print("Brak danych do wyświetlenia. Możliwe, że zaszyfrowane dane są puste lub uszkodzone.")
        return

    try:
        length = len(encrypted_image_data)
        side = int(np.sqrt(length / 3))  # Estymowanie wymiarów obrazu dla RGB
        if side * side * 3 > length:
            side -= 1

        image_array = np.frombuffer(encrypted_image_data[:side * side * 3], dtype=np.uint8).reshape((side, side, 3))
        plt.imshow(image_array)
        plt.axis('off')
        plt.title("Zaszyfrowane dane obrazu")
        plt.show()
    except Exception as e:
        print(f"Wystąpił błąd podczas wyświetlania obrazu: {str(e)}")

# Generowanie kluczy RSA
public_key, private_key = generate_rsa_keys()
original_png_path = 'example2.png'
encrypted_png_path = 'enc_example.png'
decrypted_png_path = 'dec_example.png'

# Szyfrowanie pliku PNG
print("Szyfrowanie pliku PNG...")
encrypted_image_data = modify_png(original_png_path, public_key, encrypted_png_path)

# Deszyfrowanie pliku PNG
print("Deszyfrowanie pliku PNG...")
decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path)

# Wyświetlanie oryginalnego obrazu
print("Wyświetlanie oryginalnego obrazu:")
display_image_from_bytes(read_png(original_png_path))

# Wyświetlanie zaszyfrowanego obrazu
print("Wyświetlanie zaszyfrowanego obrazu:")
display_encrypted_image(encrypted_image_data)

# Wyświetlanie odszyfrowanego obrazu
print("Wyświetlanie odszyfrowanego obrazu:")
display_image_from_bytes(read_png(decrypted_png_path))
