
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from .AESEncryption import GenerateAESKey, AESEncryption, AESDecryption
from .Config import RSA_KEY_LENGTH


def RSAEncryption(data: bytes, keyPath: str) -> bytes:
    publicKey = RSA.import_key(open(keyPath).read())
    sessionKey = GenerateAESKey()
    encryptData = AESEncryption(data, sessionKey)
    cipherRSA = PKCS1_OAEP.new(publicKey)
    encryptSessionKey = cipherRSA.encrypt(
        sessionKey)  # RSA_KEY_LENGTH / 8 Bytes Long
    return encryptSessionKey + encryptData


def RSADecryption(encryptData: bytes, keyPath: str) -> bytes:
    privateKey = RSA.import_key(open(keyPath).read())
    offset = RSA_KEY_LENGTH//8
    encryptSessionKey = encryptData[0:offset]
    encryptData = encryptData[offset:]
    cipherRSA = PKCS1_OAEP.new(privateKey)
    sessionKey = cipherRSA.decrypt(encryptSessionKey)
    data = AESDecryption(encryptData, sessionKey)
    return data
