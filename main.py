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
import base64
from stegano import lsb
import sys
from module.FastaIO import ReadFasta, WriteFasta
from module.FastaEncryption import EncryptFasta, DecryptFasta
from module.Config import TEMPLATE_IMAGE, TEMPLATE_IMAGE_FORMAT


def main(mode=None, filePath=None, rsaKeyPath=None, outputPath=None, processAsImage=None):
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
        if processAsImage == None:
            processAsImage = input(
                "Process as Image [y/n]: ").lower()[0] == "y"
        fastaList = ReadFasta(filePath)
        encryptData = EncryptFasta(fastaList, rsaKeyPath)
        if processAsImage:
            image = lsb.hide(TEMPLATE_IMAGE, base64.b64encode(
                encryptData).decode('ascii'))
            image.save(outputPath, format=TEMPLATE_IMAGE_FORMAT)
        else:
            with open(outputPath, "wb") as f:
                f.write(encryptData)
        print("Complete Encrypt Data")
    elif mode == "d":
        print("Decrypt Mode")
        if filePath == None:
            filePath = input("Enter Filepath to Decrypt: ")
        if rsaKeyPath == None:
            rsaKeyPath = input("Enter RSA Private Key Filepath: ")
        if outputPath == None:
            outputPath = input("Enter Output Filepath: ")
        if processAsImage == None:
            processAsImage = input(
                "Process as Image [y/n]: ").lower()[0] == "y"
        encryptData = None
        if processAsImage:
            encryptData = base64.b64decode(lsb.reveal(filePath) + '==')
        else:
            with open(filePath, "rb") as f:
                encryptData = f.read()
        data = DecryptFasta(encryptData, rsaKeyPath)
        WriteFasta(outputPath, data)
        print("Complete Decrypt Data")


mode = None
filePath = None
rsaKeyPath = None
outputPath = None
processAsImage = None
if len(sys.argv) > 1:
    mode = sys.argv[1]
if len(sys.argv) > 2:
    filePath = sys.argv[2]
if len(sys.argv) > 3:
    rsaKeyPath = sys.argv[3]
if len(sys.argv) > 4:
    outputPath = sys.argv[4]
if len(sys.argv) > 5:
    processAsImage = sys.argv[5].strip().lower() == "true"
main(mode, filePath, rsaKeyPath, outputPath, processAsImage)
