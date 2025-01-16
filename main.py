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

app = Flask(__name__)
CORS(app)

try:
    uri = "mongodb+srv://thuccua2004:VB39hefIin7Riwx8@cluster0.28nrq.mongodb.net/"
    client = MongoClient(uri)
    db = client["JackWallet"]['datas']
    print("Kết nối MongoDB thành công!")
except Exception as e:
    print(f"Kết nối MongoDB thất bại: {e}")
def AddDataDB(address_wallet):
    try:
        user_data = {
            "address_wallet": address_wallet,
        }
        db.insert_one(user_data)
        print("✅ Dữ liệu đã được thêm vào MongoDB!")
    except Exception as e:
        print(f"Lỗi khi thêm dữ liệu vào MongoDB: {e}")

def generate_key_pair(private_key):
    if isinstance(private_key, str):
        private_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    
    public_key = private_key.get_verifying_key()
    public_key_hex = public_key.to_string().hex()
    
    return public_key_hex

def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def generate_bitcoin_address(public_key_hex):
    sha256_pk = sha256(bytes.fromhex(public_key_hex))
    ripemd160_pk = ripemd160(sha256_pk)
    versioned_pk = b'\x00' + ripemd160_pk
    checksum = sha256(sha256(versioned_pk))[:4]
    binary_address = versioned_pk + checksum
    address = base58.b58encode(binary_address).decode()
    return address

def generate_wallet():
    mnemo = Mnemonic("english")
    mnemonic = mnemo.generate(strength=256)
    
    seed = mnemo.to_seed(mnemonic)
    
    private_key_bytes = hashlib.sha256(seed).digest()
    private_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    
    return {
        'mnemonic': mnemonic,
        'private_key': private_key 
    }


# giải mã seed
def recover_from_mnemonic(mnemonic):
    mnemo = Mnemonic("english")
    if not mnemo.check(mnemonic):
        raise ValueError("Invalid seed phrase")
    seed = mnemo.to_seed(mnemonic)
    private_key_bytes = hashlib.sha256(seed).digest()
    private_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    return private_key

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    data = request.get_json()
    password = data.get('password').encode('utf-8')
    
    salt = get_random_bytes(16)
    key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
    Wallet = generate_wallet()
    private_key = Wallet['private_key']
    mnemonic = Wallet['mnemonic']
    public_key = generate_key_pair(private_key)
    Wallet_address = generate_bitcoin_address(public_key)
    private_key_bytes = private_key.to_string() 
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(private_key_bytes, AES.block_size))
    encrypted_private_key = ciphertext.hex()
    iv_hex = iv.hex()
    AddDataDB(Wallet_address)
   
    return jsonify({
        'encrypted_private_key': encrypted_private_key,
        # 'private_key': private_key.to_string().hex(),
        'mnemonic': mnemonic,
        'iv': iv_hex,
        'Wallet_address': Wallet_address,
        'salt': salt.hex()
    })


# lấy lại private_key bằng seed
@app.route('/restore-wallet', methods=['POST'])
def recover_Wallet():
    data = request.get_json()
    mnemonic = data.get('mnemonic')
    password = data.get('password')
    salt = get_random_bytes(16)
    key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
    private_key = recover_from_mnemonic(mnemonic)
    public_key = generate_key_pair(private_key)
    Wallet_address = generate_bitcoin_address(public_key)
    private_key_bytes = private_key.to_string() 
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(private_key_bytes, AES.block_size))
    encrypted_private_key = ciphertext.hex()
    iv_hex = iv.hex()
    return jsonify({
        'encrypted_private_key': encrypted_private_key,
        'private_key': private_key.to_string().hex(),
        'mnemonic': mnemonic,
        'iv': iv_hex,
        'Wallet_address': Wallet_address,
        'salt': salt.hex()
    })

@app.route('/connect-wallet', methods=['POST'])
def Connect_Wallet():
    data = request.get_json()
    password = data.get('password')
    encrypted_private_key = data.get('encrypted_private_key')
    iv = data.get('iv')
    salt = data.get('salt')
    if not all([password, encrypted_private_key, iv, salt]):
        return jsonify({
            'Code': 400,
            'Message': 'Thiếu dữ liệu đầu vào.'
        })
    password = password.encode('utf-8')
    encrypted_private_key = bytes.fromhex(encrypted_private_key)
    iv = bytes.fromhex(iv)
    salt = bytes.fromhex(salt)

    reconstructed_key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
    cipher = AES.new(reconstructed_key, AES.MODE_CBC, iv=iv)
    try:
        decrypted_private_key = unpad(cipher.decrypt(encrypted_private_key), AES.block_size)
        return jsonify({
            'Code': 200,
            'decrypted_private_key': decrypted_private_key.hex()
        })
    except (ValueError, TypeError):
        return jsonify({
            'Code': 300,
            'decrypted_private_key': 'Null'
        })

if __name__ == '__main__':
    app.run(debug=True)