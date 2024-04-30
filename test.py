import sys
import zlib
import struct
from PIL import Image
from sympy import randprime

from rsa import rsa_encrypt


# Funkcja do zapisywania odszyfrowanych danych do pliku PNG
def save_decrypted_data_to_png(decrypted_data, save_path):
    try:
        # Tworzymy obiekt obrazu PIL z odszyfrowanymi danymi
        img = Image.frombytes('RGB', (1, len(decrypted_data) // 3), decrypted_data)
        # Zapisujemy obraz do pliku PNG
        img.save(save_path, 'PNG')
        print("Plik PNG z odszyfrowanymi danymi został pomyślnie zapisany.")
    except Exception as e:
        print(f"Błąd przy zapisie pliku PNG: {e}")


# Generowanie kluczy RSA
def generate_rsa_keys(bits=1024):
    p = randprime(2 ** (bits // 2 - 1), 2 ** (bits // 2))
    q = randprime(2 ** (bits // 2 - 1), 2 ** (bits // 2))
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)  # Obliczanie d jako odwrotność e modulo phi
    return (e, n), (d, n)


# Funkcja deszyfrująca dane z wykorzystaniem klucza prywatnego
def rsa_decrypt(data, private_key):
    d, n = private_key
    byte_length = (n.bit_length() + 7) // 8
    decrypted_data = bytearray()
    for i in range(0, len(data), byte_length):
        encrypted_val = int.from_bytes(data[i:i + byte_length], byteorder='big')
        decrypted_val = pow(encrypted_val, d, n)
        decrypted_data.extend(decrypted_val.to_bytes(byte_length, byteorder='big'))
    return bytes(decrypted_data)


# Testowanie algorytmu deszyfrowania
def test_decryption():
    # Wygenerujmy dane testowe do zaszyfrowania
    original_data = b"Testowy ciag bajtow do zaszyfrowania."

    # Wygenerujmy klucze RSA
    public_key, private_key = generate_rsa_keys(bits=512)

    # Zaszyfrujmy dane testowe
    encrypted_data = rsa_encrypt(original_data, public_key)

    # Odszyfrujmy zaszyfrowane dane
    decrypted_data = rsa_decrypt(encrypted_data, private_key)

    # Sprawdzamy, czy odszyfrowane dane są zgodne z oryginalnymi danymi
    if original_data == decrypted_data:
        print("Algorytm deszyfrowania działa poprawnie.")
    else:
        print("Błąd w algorytmie deszyfrowania.")

    # Zapiszmy odszyfrowane dane do pliku PNG
    save_decrypted_data_to_png(decrypted_data, "decrypted_test_image.png")


# Wywołanie testu deszyfrowania
test_decryption()
