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
