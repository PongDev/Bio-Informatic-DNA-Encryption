import json
from .DNANumericBase import numericBaseToDNA, dnaToNumericBase
from .Huffman import encodeHuffman, decodeHuffman
from .RSAEncryption import RSAEncryption, RSADecryption
from .Config import MAX_DATA_BYTE_LENGTH, ENCODE_ENDIAN


def EncryptFasta(fastaList: list, keyPath: str) -> bytes:
    r = bytes()
    metaData = []
    allDNAStr = ""
    for dnaName, dnaStr in fastaList:
        metaData.append((dnaName, len(dnaStr)))
        allDNAStr += dnaStr
    metaDataBytes = json.dumps(metaData).encode('ascii')
    allDNAStr = encodeHuffman(dnaToNumericBase(allDNAStr))
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
    dnaData = numericBaseToDNA(decodeHuffman(dnaData))
    metaData = json.loads(metaData)
    offset = 0
    for dnaName, dnaLen in metaData:
        r.append((dnaName, dnaData[offset:offset+dnaLen]))
        offset += dnaLen
    return r
