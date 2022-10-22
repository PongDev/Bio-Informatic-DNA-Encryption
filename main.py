"""
Output File Structure

Header
AES encryption key encrypt with RSA
---------- Encrypt with AES ----------
MetaData
    Name
    SubDNACount
    SubDNALengthArray
DNA (Combine of all DNA)
    EncodingTableLength
    EncodingDNALength
    SplitLength
    ZeroFillLength
    EncodingTable
    EncodingDNA
"""

import json
from dahuffman import HuffmanCodec
from numpy import base_repr as intToBaseStr
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import sys
from stegano import lsb
import base64

ENCODE_ENDIAN = 'big'
HUFFMAN_TABLE_BYTE_LENGTH = 4
ENCODE_BYTE_LENGTH = 8
MAX_DATA_BYTE_LENGTH = 8
SPLIT_LENGTH = 8
SPLIT_BYTE_LENGTH = 1  # Require at least log2 of max SPLIT_LENGTH bit
ZEROFILL_BYTE_LENGTH = 1  # Require at least log2 of max SPLIT_LENGTH bit

# Must be 16 for AES-128 / 24 for AES-192 / 32 for AES-256
AES_ENCRYPTION_KEY_LENGTH = 32
RSA_KEY_LENGTH = 2048

TEMPLATE_IMAGE = "template.png"
TEMPLATE_IMAGE_FORMAT = "png"


mp = {'A': '00', 'T': '01', 'C': '10', 'G': '11'}
rmp = {}

for key, value in mp.items():
    rmp[value] = key


def dnaToBase4(dna: str) -> str:
    r = ""

    for i in dna:
        r += mp[i]
    return r


def base4ToDNA(base4: str) -> str:
    dna = ''.join([rmp[base4[idx:idx+2]] for idx in range(0, len(base4), 2)])
    return dna


def decodeHuffman(dataIn: bytes) -> str:
    huffmanTableLength = int.from_bytes(
        dataIn[0:HUFFMAN_TABLE_BYTE_LENGTH], ENCODE_ENDIAN)
    offset = HUFFMAN_TABLE_BYTE_LENGTH
    encodeLength = int.from_bytes(
        dataIn[offset:offset+ENCODE_BYTE_LENGTH], ENCODE_ENDIAN)
    offset += ENCODE_BYTE_LENGTH
    splitLen = int.from_bytes(
        dataIn[offset:offset+SPLIT_BYTE_LENGTH], ENCODE_ENDIAN)
    offset += SPLIT_BYTE_LENGTH
    zeroFill = int.from_bytes(
        dataIn[offset:offset+ZEROFILL_BYTE_LENGTH], ENCODE_ENDIAN)
    offset += ZEROFILL_BYTE_LENGTH
    huffmanFreq = json.loads(dataIn[offset:offset+huffmanTableLength])
    codec = HuffmanCodec.from_frequencies(
        {chr(int(k)): v for (k, v) in huffmanFreq.items()})
    offset += huffmanTableLength
    encodeData = dataIn[offset:offset+encodeLength]
    decodeData = codec.decode(encodeData)
    decodeData = ''.join([intToBaseStr(ord(i), base=2).zfill(splitLen)
                          for i in decodeData])
    if zeroFill != 0:
        decodeData = decodeData[:-zeroFill]
    return decodeData


def encodeHuffman(dataIn: str) -> bytes:
    minResultLen = None
    result = None
    for splitLen in range(SPLIT_LENGTH):
        splitLen += 1
        tmp = [int(dataIn[idx:idx+splitLen].ljust(splitLen, '0'), 2)
               for idx in range(0, len(dataIn), splitLen)]
        zeroFill = 0
        if len(dataIn) % SPLIT_LENGTH != 0:
            zeroFill = SPLIT_LENGTH-(len(dataIn) % SPLIT_LENGTH)
        huffmanFreq: dict = {}
        for i in tmp:
            if i in huffmanFreq:
                huffmanFreq[i] += 1
            else:
                huffmanFreq[i] = 1

        huffmanTable = json.dumps(huffmanFreq).encode('ascii')
        codec = HuffmanCodec.from_frequencies(
            {chr(k): v for (k, v) in huffmanFreq.items()})
        result = codec.encode(''.join([chr(i) for i in tmp]))
        encodeString = len(huffmanTable).to_bytes(HUFFMAN_TABLE_BYTE_LENGTH, ENCODE_ENDIAN) + \
            len(result).to_bytes(ENCODE_BYTE_LENGTH, ENCODE_ENDIAN) + \
            splitLen.to_bytes(SPLIT_BYTE_LENGTH, ENCODE_ENDIAN) + \
            zeroFill.to_bytes(ZEROFILL_BYTE_LENGTH, ENCODE_ENDIAN) + \
            huffmanTable + result
        if minResultLen == None or len(encodeString) < minResultLen:
            minResultLen = len(encodeString)
            result = encodeString
    return encodeString


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


def ReadFasta(filePath: str) -> list:
    r = []

    dnaName = None
    dnaStr = ""
    with open(filePath, 'r') as f:
        for line in f:
            line = line.strip()
            if len(line) == 0:
                continue
            if line[0] == '>':
                if dnaName != None and dnaStr != "":
                    r.append((dnaName, dnaStr))
                dnaName = line[1:]
                dnaStr = ""
            else:
                dnaStr += line
        if dnaName != None and dnaStr != "":
            r.append((dnaName, dnaStr))
    return r


def WriteFasta(filePath: str, fastaList: list) -> None:
    with open(filePath, 'w') as f:
        for dnaName, dnaStr in fastaList:
            f.write(f">{dnaName}\n{dnaStr}\n")


def EncryptFasta(fastaList: list, keyPath: str) -> bytes:
    r = bytes()
    metaData = []
    allDNAStr = ""
    for dnaName, dnaStr in fastaList:
        metaData.append((dnaName, len(dnaStr)))
        allDNAStr += dnaStr
    metaDataBytes = json.dumps(metaData).encode('ascii')
    allDNAStr = encodeHuffman(dnaToBase4(allDNAStr))
    encryptMetaData = RSAEncryption(metaDataBytes, keyPath)
    encryptDNAStr = RSAEncryption(allDNAStr, keyPath)
    r += len(encryptMetaData).to_bytes(MAX_DATA_BYTE_LENGTH, ENCODE_ENDIAN) + \
        len(encryptDNAStr).to_bytes(MAX_DATA_BYTE_LENGTH, ENCODE_ENDIAN) + \
        encryptMetaData + encryptDNAStr
    return r


def DecryptFasta(encryptData: bytes, keyPath: str) -> list:
    r = []
    encryptMetaDataLen = int.from_bytes(
        encryptData[:MAX_DATA_BYTE_LENGTH], ENCODE_ENDIAN)
    offset = MAX_DATA_BYTE_LENGTH
    encryptDNADataLen = int.from_bytes(
        encryptData[offset:offset+MAX_DATA_BYTE_LENGTH], ENCODE_ENDIAN)
    offset += MAX_DATA_BYTE_LENGTH
    encryptMetaData = encryptData[offset:offset+encryptMetaDataLen]
    offset += encryptMetaDataLen
    encryptDNAData = encryptData[offset:offset+encryptDNADataLen]
    metaData = RSADecryption(encryptMetaData, keyPath)
    dnaData = RSADecryption(encryptDNAData, keyPath)
    dnaData = base4ToDNA(decodeHuffman(dnaData))
    metaData = json.loads(metaData)
    offset = 0
    for dnaName, dnaLen in metaData:
        r.append((dnaName, dnaData[offset:offset+dnaLen]))
        offset += dnaLen
    return r


def main(mode=None, filePath=None, rsaKeyPath=None, outputPath=None):
    while mode not in ["e", "d"]:
        mode = input(
            'Enter "e" for encrypt "d" for decrypt\n[e/d]: ').lower()[0]
    if mode == "e":
        print("Encrypt Mode")
        if filePath == None:
            filePath = input("Enter Filepath to Encrypt: ")
        if rsaKeyPath == None:
            rsaKeyPath = input("Enter RSA Public Key Filepath: ")
        if outputPath == None:
            outputPath = input("Enter Output Filepath: ")
        fastaList = ReadFasta(filePath)
        encryptData = EncryptFasta(fastaList, rsaKeyPath)
        image = lsb.hide(TEMPLATE_IMAGE, base64.b64encode(
            encryptData).decode('ascii'))
        image.save(outputPath, format=TEMPLATE_IMAGE_FORMAT)
        print("Complete Encrypt Data")
    elif mode == "d":
        print("Decrypt Mode")
        if filePath == None:
            filePath = input("Enter Filepath to Decrypt: ")
        if rsaKeyPath == None:
            rsaKeyPath = input("Enter RSA Private Key Filepath: ")
        if outputPath == None:
            outputPath = input("Enter Output Filepath: ")
        encryptData = None
        encryptData = base64.b64decode(lsb.reveal(filePath) + '==')
        data = DecryptFasta(encryptData, rsaKeyPath)
        WriteFasta(outputPath, data)
        print("Complete Decrypt Data")


mode = None
filePath = None
rsaKeyPath = None
outputPath = None
if len(sys.argv) > 1:
    mode = sys.argv[1]
if len(sys.argv) > 2:
    filePath = sys.argv[2]
if len(sys.argv) > 3:
    rsaKeyPath = sys.argv[3]
if len(sys.argv) > 4:
    outputPath = sys.argv[4]
main(mode, filePath, rsaKeyPath, outputPath)
