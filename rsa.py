
import sys
import zlib
import struct

from sympy import randprime


def read_png(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
    return data



def generate_rsa_keys(bits=1024):
    p = randprime(2**(bits//2 - 1), 2**(bits//2))
    q = randprime(2**(bits//2 - 1), 2**(bits//2))
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)  # Obliczanie d jako odwrotność e modulo phi
    return (e, n), (d, n)

def rsa_encrypt(data, public_key):
    e, n = public_key
    byte_length = (n.bit_length() + 7) // 8
    encrypted_data = bytearray()
    for byte in data:
        encrypted_val = pow(byte, e, n)
        encrypted_data.extend(encrypted_val.to_bytes(byte_length, byteorder='big'))
    return bytes(encrypted_data)

def rsa_decrypt(data, private_key):
    d, n = private_key
    byte_length = (n.bit_length() + 7) // 8
    decrypted_data = bytearray()
    for i in range(0, len(data), byte_length):
        encrypted_val = int.from_bytes(data[i:i+byte_length], byteorder='big')
        try:
            decrypted_val = pow(encrypted_val, d, n)
            decrypted_data.append(decrypted_val % 256)
        except Exception as e:
            print(f"Błąd przy deszyfrowaniu danych: {e}")
            break
    return bytes(decrypted_data)



def modify_png(file_path, public_key, save_path):
    try:
        data = read_png(file_path)
    except IOError as e:
        print(f"Błąd przy odczycie pliku: {e}")
        sys.exit(1)

    new_png_data = bytearray()
    pos = 0

    if data[pos:pos + 8] != b'\x89PNG\r\n\x1a\n':
        print("Niepoprawny plik PNG")
        sys.exit(1)

    new_png_data.extend(data[pos:pos + 8])
    pos += 8

    while pos < len(data):
        if pos + 12 > len(data):
            print("Uszkodzony plik PNG - brakuje danych chunka.")
            break

        chunk_len = struct.unpack('>I', data[pos:pos + 4])[0]
        pos += 4
        chunk_type = data[pos:pos + 4]
        pos += 4
        if pos + chunk_len + 4 > len(data):
            print("Uszkodzony plik PNG - dane chunka niekompletne.")
            break

        chunk_data = data[pos:pos + chunk_len]
        pos += chunk_len
        crc = data[pos:pos + 4]
        pos += 4

        try:
            if chunk_type == b'IDAT':
                decompressed_data = zlib.decompress(chunk_data)
                encrypted_data = rsa_encrypt(decompressed_data, public_key)
                recompressed_data = zlib.compress(bytes(encrypted_data))
                chunk_data = recompressed_data
                chunk_len = len(chunk_data)
        except zlib.error as e:
            print(f"Błąd dekompresji danych: {e}")
            continue
        except Exception as e:
            print(f"Błąd przy szyfrowaniu danych: {e}")
            continue

        # Obliczanie nowego CRC
        new_crc = zlib.crc32(chunk_type)
        new_crc = zlib.crc32(chunk_data, new_crc)
        new_crc = struct.pack('>I', new_crc & 0xffffffff)

        new_png_data.extend(struct.pack('>I', chunk_len))
        new_png_data.extend(chunk_type)
        new_png_data.extend(chunk_data)
        new_png_data.extend(new_crc)

    try:
        with open(save_path, 'wb') as file:
            file.write(new_png_data)
    except IOError as e:
        print(f"Błąd przy zapisie pliku: {e}")
        sys.exit(1)

    print("Plik został pomyślnie zmodyfikowany i zapisany.")


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
            try:
                decompressed_data = zlib.decompress(chunk_data)
                decrypted_data = rsa_decrypt(decompressed_data, private_key)
                recompressed_data = zlib.compress(decrypted_data)
                chunk_data = recompressed_data
                chunk_len = len(chunk_data)
            except zlib.error as e:
                print(f"Błąd dekompresji danych: {e}")
                continue
            except Exception as e:
                print(f"Błąd przy deszyfrowaniu danych: {e}")
                continue

        new_crc = zlib.crc32(chunk_type)
        new_crc = zlib.crc32(chunk_data, new_crc)
        new_crc = struct.pack('>I', new_crc & 0xffffffff)
        new_png_data.extend(struct.pack('>I', chunk_len))
        new_png_data.extend(chunk_type)
        new_png_data.extend(chunk_data)
        new_png_data.extend(new_crc)

    with open(decrypted_png_path, 'wb') as file:
        file.write(new_png_data)
    print("Plik został pomyślnie odszyfrowany i zapisany.")


# Użycie:
public_key, private_key = generate_rsa_keys(bits=512)
original_png_path = "example2.png"
encrypted_png_path = "encrypted_example2.png"
decrypted_png_path = "decrypted_example2.png"

modify_png(original_png_path, public_key, encrypted_png_path)
decrypt_and_reconstruct_png(encrypted_png_path, private_key, decrypted_png_path)