from Cryptodome.PublicKey import RSA

from Cryptodome.Cipher import PKCS1_OAEP

from Cryptodome.Random import get_random_bytes

from Crypto.Cipher import AES

from Crypto.Random import get_random_bytes

from Crypto.Util.Padding import pad, unpad

import os



def generate_rsa_keypair(public_key_path, private_key_path, key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open(public_key_path, 'wb') as public_key_file:
        public_key_file.write(public_key)
    with open(private_key_path, 'wb') as private_key_file:
        private_key_file.write(private_key)
    return private_key, public_key


def encrypt_file_with_rsa(file_path, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    chunk_size = rsa_key.size_in_bytes() - 42
    ciphertext = b''
    for i in range(0, len(file_data), chunk_size):
        chunk = file_data[i:i+chunk_size]
        ciphertext += cipher_rsa.encrypt(chunk)
    return ciphertext

def encrypt_directory(directory_path, public_key_path):
    with open(public_key_path, 'rb') as file:
        key_value = file.read()
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypted_content = encrypt_file_with_rsa(file_path, key_value)
            with open(file_path, 'wb') as file:
                file.write(encrypted_content)



def decrypt_rsa(file_path, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    chunk_size = rsa_key.size_in_bytes()
    decrypted_data = b''
    with open(file_path, 'rb') as file:
        ciphertext = file.read()
    for i in range(0, len(ciphertext), chunk_size):
        chunk = ciphertext[i:i+chunk_size]
        decrypted_data += cipher_rsa.decrypt(chunk)
    return decrypted_data

def decrypt_directory(directory_path, private_key_path):
    with open(private_key_path, 'rb') as private_key_file:
        private_key = private_key_file.read()
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            decrypted_content = decrypt_rsa(file_path, private_key)
            with open(file_path, 'wb') as file:
                file.write(decrypted_content)


public_key_path = "public-key"
private_key_path = "private-key"

generate_rsa_keypair(public_key_path, private_key_path, key_size=2048)

