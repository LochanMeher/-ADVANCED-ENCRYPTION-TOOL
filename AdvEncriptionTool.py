import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password)

def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)
    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted = aesgcm.encrypt(nonce, data, None)

    with open(file_path + ".enc", 'wb') as f:
        f.write(salt + nonce + encrypted)

    print(f"File encrypted successfully: {file_path}.enc")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(12)
        ciphertext = f.read()

    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)

    try:
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print("Decryption failed:", e)
        return

    original_file = file_path.replace(".enc", ".dec")
    with open(original_file, 'wb') as f:
        f.write(decrypted)

    print(f"File decrypted successfully: {original_file}")

if __name__ == "__main__":
    action = input("Encrypt or Decrypt? (e/d): ").lower()
    path = input("File path: ")
    pwd = getpass("Password: ")

    if action == 'e':
        encrypt_file(path, pwd)
    elif action == 'd':
        decrypt_file(path, pwd)
    else:
        print("Invalid option.")
