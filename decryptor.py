from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib


def decrypt_file(encrypted_file_path, key):
    try:
        with open(encrypted_file_path, 'rb') as encrypted_file:
            iv = encrypted_file.read(16)
            ciphertext = encrypted_file.read()

        cipher = AES.new(hashlib.sha256(key.encode()).digest(), AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        decrypted_file_path = encrypted_file_path[:-4]  # Remove ".enc" from the file name
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)

        print("Decryption completed successfully. Decrypted file: " + decrypted_file_path)

    except Exception as e:
        print("Decryption failed: " + str(e))


# Usage example:
encrypted_file_path = "jadhusan.txt.enc"
encryption_key = "jadhusan"

decrypt_file(encrypted_file_path, encryption_key)
