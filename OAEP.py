#! /usr/bin/python
#
# OAEP.py - Adding OAEP padding module to the RSA implementation.
#
# Shiyi Cao 2019.6.30

import hashlib
import random
import time
import RSA

K0 = K1 = 256
p = 0
q = 0
e = 65537
n = 0
eular = 0


def generateKey(bits=1024):
    global p, q, n, e, d, eular
    start = time.time()
    bits >>= 1
    e = 65537
    p = RSA.get_prime(bits)
    q = RSA.get_prime(bits)
    n = p * q
    eular = (p - 1) * (q - 1)
    x, y = RSA.get_(e, eular)
    d = x % eular
    return e, d, n


def encrypt(message, e, n):
    global K0, K1
    valueMessage = int(message, 16)
    r = random.randrange(1 << (K0 - 1), (1 << K0) - 1)
    keccak = hashlib.sha384(hex(r).encode('utf-8'))
    Gr = int(keccak.hexdigest(), 16)  # 384 bits
    X = (valueMessage << K1) ^ Gr
    keccak = hashlib.sha256(hex(X).encode('utf-8'))
    Hx = int(keccak.hexdigest(), 16)  # 256 bits
    Y = r ^ Hx
    res = (X << K0) + Y
    # RSA encryption
    encrypt = RSA.fastExpMod(res, e, n)
    return encrypt


def decrypt(encrypt, d, n):
    global K0, K1
    # RSA decryption
    encryptValue = RSA.fastExpMod(encrypt, d, n)

    Y = encryptValue % (1 << K0)
    X = encryptValue >> K0
    keccak = hashlib.sha256(hex(X).encode('utf-8'))
    Hx = int(keccak.hexdigest(), 16)  # 256 bits
    r = Y ^ Hx
    keccak = hashlib.sha384(hex(r).encode('utf-8'))
    Gr = int(keccak.hexdigest(), 16)  # 384 bits
    message = X ^ Gr
    message >>= K1
    return hex(message)


'''================================TESTING======================================'''
start = time.time()
a, b, c = generateKey()
message = "0x592fa743889fc7f92ac2a37bb1f5ba1d"
encrypt = encrypt(message, a, c)
print("Encrypted Message:", encrypt)
decrypt = decrypt(encrypt, b, c)
print("Decrypted Message:", decrypt)
if int(decrypt, 16) == int(message, 16):
    print("Decrypt successful!!")
else:
    print("Error decryption!!")
print(time.time() - start)
