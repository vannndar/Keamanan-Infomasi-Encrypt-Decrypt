from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import os

# Fungsi enkripsi


def encrypt_file(file_data, algorithm):
    key = os.urandom(16)  # Generate random key (untuk AES)
    iv = os.urandom(16)  # Initialization Vector (untuk AES)

    if algorithm == 'AES':
        iv = get_random_bytes(AES.block_size)  # IV untuk AES
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
    elif algorithm == 'DES':
        key = get_random_bytes(8)  # Kunci untuk DES harus 8 byte
        iv = get_random_bytes(DES.block_size)  # IV untuk DES
        cipher = DES.new(key, DES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(file_data, DES.block_size))
    elif algorithm == 'RC4':
        key = get_random_bytes(16)  # Panjang kunci untuk RC4, bisa disesuaikan
        cipher = ARC4.new(key)
        encrypted_data = cipher.encrypt(file_data)
        iv = None  # RC4 tidak menggunakan IV

    # Kembalikan data yang telah dienkripsi, kunci, dan IV
    return encrypted_data, key, iv


# Fungsi dekripsi
def decrypt_file(encrypted_data, algorithm, key, iv=None):
    if algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    elif algorithm == 'DES':
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)
    elif algorithm == 'RC4':
        cipher = ARC4.new(key)
        decrypted_data = cipher.decrypt(encrypted_data)

    return decrypted_data
