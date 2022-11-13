# Bio Informatic DNA Encryption

## Requirement
- python3 with pip installed

## Installation
`pip install -r requirements.txt`

## Configuration
- copy .env.template and rename to .env
- configuration according to .env file

## Usage
`python3 main.py`

or

`python3 main.py [mode e or d] [Input/Output File Path] [Public/Private RSA Key Path] [Output Path] [Process as Image true or false]`

For Encryption

`python3 main.py e [Input File Path] [Public RSA Key Path] [Output Path] [Output as Image true or false]`

For Decryption

`python3 main.py d [Output File Path] [Private RSA Key Path] [Output Path] [Input File is Encrypt as Image true or false]`