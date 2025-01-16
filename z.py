import hashlib
import base58
import bip39
from mnemonic import Mnemonic
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, jsonify, request
from flask_cors import CORS
from Crypto.PublicKey import ECC
from pymongo import MongoClient

def recover_from_mnemonic(mnemonic):
    mnemo = Mnemonic("english")
    if not mnemo.check(mnemonic):
        raise ValueError("Invalid seed phrase")
    seed = mnemo.to_seed(mnemonic)
    
    # Tạo lại private key
    private_key_bytes = hashlib.sha256(seed).digest()
    private_key = private_key_bytes.hex()
    
    return private_key
if __name__ == "__main__":
    # Khôi phục private key từ seed phrase
    recovered_key = recover_from_mnemonic('')
    print("Recovered Private Key:", recovered_key)