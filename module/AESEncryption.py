from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from .Config import AES_ENCRYPTION_KEY_LENGTH


def GenerateAESKey() -> bytes:
    return get_random_bytes(AES_ENCRYPTION_KEY_LENGTH)


def AESEncryption(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce  # 16 bytes random nonce
    encryptData, tag = cipher.encrypt_and_digest(data)  # 16 bytes tag
    return nonce + tag + encryptData


def AESDecryption(encryptData: bytes, key: bytes) -> bytes:
    nonce = encryptData[0:16]
    tag = encryptData[16:32]
    encryptData = encryptData[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decryptData = cipher.decrypt(encryptData)
    try:
        cipher.verify(tag)
        return decryptData
    except:
        return bytes()
