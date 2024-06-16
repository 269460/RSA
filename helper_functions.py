from sympy import randprime, isprime
import random
import math
import matplotlib.pyplot as plt
from PIL import Image
import numpy as np
import io

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
