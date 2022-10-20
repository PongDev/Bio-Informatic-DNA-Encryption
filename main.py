import json
from dahuffman import HuffmanCodec
from copy import deepcopy

ENCODE_ENDIAN = 'big'
HUFFMAN_TABLE_BYTE_LENGTH = 4
RESULT_BYTE_LENGTH = 8
SPLIT_LENGTH = 8


mp = {'A': '00', 'T': '01', 'C': '10', 'G': '11'}
rmp = {}

for key, value in mp.items():
    rmp[value] = key


def dnaToBase4(dna: str) -> str:
    r = ""

    for i in dna:
        r += mp[i]
    return len(dna), r


def encodeHuffman(dataIn: str) -> bytes:
    minResultLen = None
    result = None
    for splitLen in range(SPLIT_LENGTH):
        splitLen += 1
        tmp = [int(dataIn[idx:idx+splitLen], 2)
               for idx in range(0, len(dataIn), splitLen)]
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
            huffmanTable+len(result).to_bytes(RESULT_BYTE_LENGTH,
                                              ENCODE_ENDIAN)+result
        if minResultLen == None or len(encodeString) < minResultLen:
            minResultLen = len(encodeString)
            result = encodeString
    return encodeString
