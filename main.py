from copy import deepcopy
from dahuffman import HuffmanCodec
import json

mp = {'A': '00', 'T': '01', 'C': '10', 'G': '11'}
rmp = {}

for key, value in mp.items():
    rmp[value] = key


def dnaToBase4(dna: str) -> str:
    r = ""

    for i in dna:
        r += mp[i]
    return len(dna), r


def encodeHuffman(dataIn: str):  # -> tuple(int, bytes):
    for splitLen in range(8):
        splitLen += 1
        tmp = [int(dataIn[idx:idx+splitLen], 2)
               for idx in range(0, len(dataIn), splitLen)]
        huffmanFreq: dict = {}
        for i in tmp:
            if i in huffmanFreq:
                huffmanFreq[i] += 1
            else:
                huffmanFreq[i] = 1

        decodeTable = json.dumps(huffmanFreq).encode('ascii')
        codec = HuffmanCodec.from_frequencies(
            {chr(k): v for (k, v) in huffmanFreq.items()})
        result = codec.encode(''.join([chr(i) for i in tmp]))
        encodeString = len(decodeTable).to_bytes(4, 'big') + \
            decodeTable+len(result).to_bytes(8, 'big')+result
        print(len(encodeString))
