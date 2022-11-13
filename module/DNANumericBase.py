mapTable = {'A': '00', 'T': '01', 'C': '10', 'G': '11'}
reverseMaptable = {}

for key, value in mapTable.items():
    reverseMaptable[value] = key


def dnaToBase4(dna: str) -> str:
    r = ""

    for i in dna:
        r += mapTable[i]
    return r


def base4ToDNA(base4: str) -> str:
    dna = ''.join([reverseMaptable[base4[idx:idx+2]] for idx in range(0, len(base4), 2)])
    return dna
