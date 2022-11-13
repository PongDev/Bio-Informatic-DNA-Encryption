from dahuffman import HuffmanCodec
from numpy import base_repr as intToBaseStr
import json
from .Config import HUFFMAN_TABLE_BYTE_LENGTH, ENCODE_ENDIAN, ENCODE_BYTE_LENGTH, MAX_SPLIT_LENGTH, MAX_SPLIT_BYTE_LENGTH, ZEROFILL_BYTE_LENGTH


def decodeHuffman(dataIn: bytes) -> str:
    huffmanTableLength = int.from_bytes(
        dataIn[0:HUFFMAN_TABLE_BYTE_LENGTH], ENCODE_ENDIAN)
    offset = HUFFMAN_TABLE_BYTE_LENGTH
    encodeLength = int.from_bytes(
        dataIn[offset:offset+ENCODE_BYTE_LENGTH], ENCODE_ENDIAN)
    offset += ENCODE_BYTE_LENGTH
    splitLen = int.from_bytes(
        dataIn[offset:offset+MAX_SPLIT_BYTE_LENGTH], ENCODE_ENDIAN)
    offset += MAX_SPLIT_BYTE_LENGTH
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
    minResult = None
    for splitLen in range(MAX_SPLIT_LENGTH):
        splitLen += 1
        tmp = [int(dataIn[idx:idx+splitLen].ljust(splitLen, '0'), 2)
               for idx in range(0, len(dataIn), splitLen)]
        zeroFill = 0
        if len(dataIn) % splitLen != 0:
            zeroFill = splitLen-(len(dataIn) % splitLen)
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
            splitLen.to_bytes(MAX_SPLIT_BYTE_LENGTH, ENCODE_ENDIAN) + \
            zeroFill.to_bytes(ZEROFILL_BYTE_LENGTH, ENCODE_ENDIAN) + \
            huffmanTable + result
        if minResultLen == None or len(encodeString) < minResultLen:
            minResultLen = len(encodeString)
            minResult = encodeString
    return minResult
