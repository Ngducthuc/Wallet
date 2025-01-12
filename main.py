from ecdsa import SigningKey, SECP256k1
import hashlib
import base58
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
            "value": 100
        }
        db.insert_one(user_data)
        print("✅ Dữ liệu đã được thêm vào MongoDB!")
    except Exception as e:
        print(f"Lỗi khi thêm dữ liệu vào MongoDB: {e}")

def generate_key_pair():
    private_key = SigningKey.generate(curve=SECP256k1)
    private_key_hex = private_key.to_string().hex()
    public_key = private_key.get_verifying_key()
    public_key_hex = public_key.to_string().hex()
    return private_key_hex, public_key_hex

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

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    data = request.get_json()
    password = data.get('password').encode('utf-8')
    salt = get_random_bytes(16)

    key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
    private_key, public_key = generate_key_pair()
    Wallet_address = generate_bitcoin_address(public_key)

    private_key_bytes = bytes.fromhex(private_key)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(private_key_bytes, AES.block_size))

    encrypted_private_key = ciphertext.hex()
    iv_hex = iv.hex()
    AddDataDB(Wallet_address)
    return jsonify({
        'encrypted_private_key': encrypted_private_key,
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