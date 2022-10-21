from Crypto.PublicKey import RSA

RSA_KEY_LENGTH = 2048

key = RSA.generate(RSA_KEY_LENGTH)
privateKey = key.export_key()
with open("private.key", "wb") as f:
    f.write(privateKey)

publicKey = key.public_key().export_key()
with open("public.key", "wb") as f:
    f.write(publicKey)
