from dotenv import load_dotenv
import os

load_dotenv()

# Select 'little' or 'big' Endian
ENCODE_ENDIAN = os.getenv('ENCODE_ENDIAN')
HUFFMAN_TABLE_BYTE_LENGTH = int(os.getenv('HUFFMAN_TABLE_BYTE_LENGTH'))
ENCODE_BYTE_LENGTH = int(os.getenv('ENCODE_BYTE_LENGTH'))
MAX_DATA_BYTE_LENGTH = int(os.getenv('MAX_DATA_BYTE_LENGTH'))
MAX_SPLIT_LENGTH = int(os.getenv('MAX_SPLIT_LENGTH'))

# Require at least log2 of max SPLIT_LENGTH bit
MAX_SPLIT_BYTE_LENGTH = int(os.getenv('MAX_SPLIT_BYTE_LENGTH'))

# Require at least log2 of max SPLIT_LENGTH bit
ZEROFILL_BYTE_LENGTH = int(os.getenv('ZEROFILL_BYTE_LENGTH'))

# Must be 16 for AES-128 / 24 for AES-192 / 32 for AES-256
AES_ENCRYPTION_KEY_LENGTH = int(os.getenv('AES_ENCRYPTION_KEY_LENGTH'))
RSA_KEY_LENGTH = int(os.getenv('RSA_KEY_LENGTH'))

TEMPLATE_IMAGE = os.getenv('TEMPLATE_IMAGE')
TEMPLATE_IMAGE_FORMAT = os.getenv('TEMPLATE_IMAGE_FORMAT')
