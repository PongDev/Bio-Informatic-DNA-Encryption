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
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

ENCODE_ENDIAN = 'big'
HUFFMAN_TABLE_BYTE_LENGTH = 4
ENCODE_BYTE_LENGTH = 8
SPLIT_LENGTH = 8
SPLIT_BYTE_LENGTH = 1  # Require at least log2 of max SPLIT_LENGTH bit
ZEROFILL_BYTE_LENGTH = 1  # Require at least log2 of max SPLIT_LENGTH bit


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
    decodeData = decodeData[:-zeroFill]
    return decodeData


def encodeHuffman(dataIn: str) -> bytes:
    minResultLen = None
    result = None
    for splitLen in range(SPLIT_LENGTH):
        splitLen += 1
        tmp = [int(dataIn[idx:idx+splitLen].ljust(splitLen, '0'), 2)
               for idx in range(0, len(dataIn), splitLen)]
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


def GenerateAES16BytesKey() -> bytes:
    return get_random_bytes(16)


def AESEncryption(data: bytes, key16Bytes: bytes) -> bytes:
    cipher = AES.new(key16Bytes, AES.MODE_EAX)
    nonce = cipher.nonce  # 16 bytes random nonce
    encryptData, tag = cipher.encrypt_and_digest(data)  # 16 bytes tag
    return nonce + tag + encryptData


def AESDecryption(encryptData: bytes, key16Bytes: bytes) -> bytes:
    nonce = encryptData[0:16]
    tag = encryptData[16:32]
    encryptData = encryptData[32:]
    cipher = AES.new(key16Bytes, AES.MODE_EAX, nonce=nonce)
    decryptData = cipher.decrypt(encryptData)
    try:
        cipher.verify(tag)
        return decryptData
    except:
        return bytes()


test = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
print(test)
print()
key = GenerateAES16BytesKey()
print(key)
print()
etest = AESEncryption(test, key)
print(etest)
print()
dtest = AESDecryption(etest, key)
print(dtest)
print()
print(len(test), len(etest), len(dtest))
exit()
inputData = input()
tmp = dnaToBase4(inputData)
print("Base 4 DNA")
print(tmp)
print()
encodeData = encodeHuffman(tmp)
print("Encode Data")
print(encodeData)
print()
decodeData = decodeHuffman(encodeData)
print("Decode Data")
print(decodeData)
print()
print("Decode Base 4 to DNA")
print(base4ToDNA(decodeData))
print(len(inputData))
print(len(encodeData))
