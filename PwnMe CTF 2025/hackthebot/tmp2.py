from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import hashlib


secret = ''
key = 'peanuts'

def decrypt_chrome_secrets2(encrypted_value, safe_storage_key):
    if not encrypted_value:
        return ""  # Return empty string for empty encrypted value

    iv = b' ' * 16
    key = hashlib.pbkdf2_hmac('sha1', safe_storage_key, b'saltysalt', 1003)[:16]

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)

    # Check and remove version tag
    if encrypted_value[:3] == b'v10':
        encrypted_payload = encrypted_value[3:]
    else:
        raise ValueError("Invalid version tag")

    decrypted_pass = cipher.decrypt(encrypted_payload)

    # Remove PKCS7 padding
    padding_length = decrypted_pass[-1]
    padding_value = decrypted_pass[-padding_length:]

    if padding_length > 0 and all(value == padding_length for value in padding_value):
        decrypted_pass = decrypted_pass[:-padding_length]
    else:
        raise ValueError("Invalid padding")

    decrypted_pass = decrypted_pass.decode("utf-8", "ignore")

    return decrypted_pass