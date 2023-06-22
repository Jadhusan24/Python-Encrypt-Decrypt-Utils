from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os


def encrypt_file(file_path, key, encryption_method):
    try:
        if encryption_method == "AES":
            cipher = AES.new(hashlib.sha256(key.encode()).digest(), AES.MODE_CBC)
        else:
            raise ValueError("Invalid encryption method. Supported methods: AES")

        with open(file_path, 'rb') as file:
            plaintext = file.read()

        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(cipher.iv)
            encrypted_file.write(ciphertext)

        print("Encryption completed successfully. Encrypted file: " + encrypted_file_path)

    except Exception as e:
        print("Encryption failed: " + str(e))


def decrypt_file(encrypted_file_path, key, encryption_method):
    try:
        if encryption_method == "AES":
            with open(encrypted_file_path, 'rb') as encrypted_file:
                iv = encrypted_file.read(16)
                ciphertext = encrypted_file.read()

            cipher = AES.new(hashlib.sha256(key.encode()).digest(), AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

            decrypted_file_path = os.path.splitext(encrypted_file_path)[0]  # Remove the file extension
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(plaintext)

            print("Decryption completed successfully. Decrypted file: " + decrypted_file_path)

        else:
            raise ValueError("Invalid encryption method. Supported methods: AES")

    except Exception as e:
        print("Decryption failed: " + str(e))


file_path = "jadhusan.txt"
encryption_key = "jadhusan"

encryption_method = input("Enter the encryption method (AES): ").strip().upper() or "AES"

if encryption_method != "AES":
    print("Invalid encryption method. Supported methods: AES")
else:
    encrypt_file(file_path, encryption_key, encryption_method)
    decrypt_file(file_path + ".enc", encryption_key, encryption_method)
