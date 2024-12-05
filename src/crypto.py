# -*- coding: utf-8 -*-
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


class Crypto:
    def __init__(self):
        self.aes_key = b'hF\xf9p1"\xb9\xb4\x93\x00\x9a\xa8\x99~\xad\xf8'

    # AES加密: 字符串 -> json
    def AES_Encrypt(self, data, aes_key=None):
        key = aes_key if aes_key is not None else self.aes_key
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv':iv, 'ciphertext':ct})

        return result

    # AES解密: json -> 字符串
    def AES_Decrypt(self, json_input, aes_key=None):
        try:
            b64 = json.loads(json_input)
            key = aes_key if aes_key is not None else self.aes_key
            iv = b64decode(b64['iv'])
            ct = b64decode(b64['ciphertext'])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            # print("The message was: ", pt)
            return pt.decode('utf-8')
        except (ValueError, KeyError):
            print("Incorrect decryption")

    # RSA签名: 字符串 -> 字符串
    def RSA_PSS_signature(self, message):
        key = RSA.import_key(open('src/privkey.der', 'rb').read())
        h = SHA256.new(message.encode('utf-8'))
        signature = pss.new(key).sign(h)
        return (b64encode(signature)).decode('utf-8')

    # RSA验签: 字符串,字符串 -> bool
    def RSA_PSS_verify(self, message, signature):
        key = RSA.import_key(open('src/pubkey.der', 'rb').read())
        h = SHA256.new(message.encode('utf-8'))
        verifier = pss.new(key)
        try:
            verifier.verify(h, b64decode(signature.encode('utf-8')))
            # print("The signature is authentic.")
            return True
        except (ValueError):
            # print("The signature is not authentic.")
            return False
        
    def encode_json_to_base64(self, json_obj):
        json_str = json.dumps(json_obj)
        json_bytes = json_str.encode('utf-8')
        base64_bytes = b64encode(json_bytes)
        base64_str = base64_bytes.decode('utf-8')
        return base64_str
    
    def decode_base64_to_json(self, base64_str):
        try:
            json_bytes = b64decode(base64_str)
            json_str = json_bytes.decode('utf-8')
            json_obj = json.loads(json_str)
            return json_obj
        except (ValueError):
            return None