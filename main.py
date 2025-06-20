import os
import sys
import getpass
import hashlib
import hmac
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file_with_hmac(filename, password):
    with open(filename, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    key = derive_key(password.encode(), salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)

    # حساب HMAC
    hmac_key = hashlib.sha256(key).digest()  # مفتاح HMAC منفصل
    tag = hmac.new(hmac_key, encrypted, hashlib.sha256).digest()

    output = salt + nonce + encrypted + tag

    with open(filename + ".enc", 'wb') as f:
        f.write(output)

    print(f"[+] File encrypted with HMAC -> {filename}.enc")

def decrypt_file_with_hmac(filename, password):
    with open(filename, 'rb') as f:
        raw = f.read()

    salt = raw[:16]
    nonce = raw[16:28]
    tag_stored = raw[-32:]  # آخر 32 بايت
    ciphertext = raw[28:-32]

    key = derive_key(password.encode(), salt)
    hmac_key = hashlib.sha256(key).digest()
    tag_calc = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(tag_stored, tag_calc):
        print("[-] HMAC verification failed! File may be tampered.")
        return

    aesgcm = AESGCM(key)
    try:
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        output_file = filename[:-4] if filename.endswith(".enc") else filename + ".decrypted"
        with open(output_file, 'wb') as f:
            f.write(decrypted)
        print(f"[+] File decrypted and verified -> {output_file}")
    except Exception as e:
        print(f"[-] Decryption error: {e}")

def main():
    print("=== AES-256-GCM + HMAC File Encryptor ===")
    mode = input("Mode (encrypt / decrypt): ").strip().lower()
    file = input("File path: ").strip()

    if not os.path.isfile(file):
        print("[-] File does not exist.")
        return

    pwd = getpass.getpass("Enter password: ")

    if mode == "encrypt":
        encrypt_file_with_hmac(file, pwd)
    elif mode == "decrypt":
        decrypt_file_with_hmac(file, pwd)
    else:
        print("[-] Invalid mode.")

if __name__ == "__main__":
    main()
