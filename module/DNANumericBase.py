mapTableCode = {
    '00': {'A': '00', 'T': '01', 'C': '10', 'G': '11'},
    '01': {'A': '00', 'T': '01', 'C': '10', 'U': '11'},
    '10': {'A': '000', 'T': '001', 'C': '010', 'G': '011', 'N': '100', 'U': '101', 'R': '110', 'Y': '111'},
    '11': {
        'A': '00000',
        'B': '00001',
        'C': '00010',
        'D': '00011',
        'E': '00100',
        'F': '00101',
        'G': '00110',
        'H': '00111',
        'I': '01000',
        'J': '01001',
        'K': '01010',
        'L': '01011',
        'M': '01100',
        'N': '01101',
        'O': '01110',
        'P': '01111',
        'Q': '10000',
        'R': '10001',
        'S': '10010',
        'T': '10011',
        'U': '10100',
        'V': '10101',
        'W': '10110',
        'X': '10111',
        'Y': '11000',
        'Z': '11001',
        '+': '11010',
        '-': '11011',
        '*': '11100',
        '/': '11101',
        '(': '11110',
        ')': '11111',
    },
}

reverseMapTableCode = {}

for mapTableID in sorted(mapTableCode.keys()):
    mapTable = mapTableCode[mapTableID]
    reverseMapTable = {}
    for key, value in mapTable.items():
        reverseMapTable[value] = key
    reverseMapTableCode[mapTableID] = reverseMapTable

maxMapTableCodeLength = max([len(e) for e in mapTableCode.keys()])

mapTableMetaData = {}

for mapTableID in sorted(mapTableCode.keys()):
    mapTableValueLength = [len(e) for e in mapTableCode[mapTableID].values()]
    if max(mapTableValueLength) != min(mapTableValueLength):
        raise Exception("MapTable Value Error")
    mapTableValueLength = mapTableValueLength[0]
    mapTableMetaData[mapTableID] = mapTableValueLength


for e in mapTableCode.keys():
    if len(e) != maxMapTableCodeLength:
        raise Exception("Invalid Map Table")


def declareMapTable(dna: str):
    character = set()
    for i in dna:
        character.add(i)
    for mapTableID in sorted(mapTableCode.keys()):
        mapTableCharSet = set(mapTableCode[mapTableID].keys())
        if character.issubset(mapTableCharSet):
            return mapTableID
    return None


def dnaToNumericBase(dna: str) -> str:
    mapTableID = declareMapTable(dna)
    if mapTableID == None:
        raise Exception("Unsupport Format")
    r = mapTableID

    for i in dna:
        r += mapTableCode[mapTableID][i]
    return r


def numericBaseToDNA(numericBase: str) -> str:
    mapTableID = numericBase[:maxMapTableCodeLength]
    numericBase = numericBase[maxMapTableCodeLength:]
    if mapTableID not in mapTableCode:
        raise Exception("Invalid Data")
    offset = mapTableMetaData[mapTableID]
    dna = ''.join([reverseMapTableCode[mapTableID][numericBase[idx:idx+offset]]
                   for idx in range(0, len(numericBase), offset)])
    return dna
