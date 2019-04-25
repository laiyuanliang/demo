# -*- coding:utf-8 -*-
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

#签名部分
def generateSign(dsignKey, dic):
    """ Generate a signature with SHA1...
        
    Args: 
        dsignKey: a string from server
        dic: a dictionary include parameters used to request data
    """
    sb = sorted(dic.items(), key=lambda d:d[0])
    sbstr = ''
    for item in sb:
        sbstr += f'{item[0]}={item[1]}'
    text = sbstr + '~' + dsignKey
    print(f'String for signature:\n {text}')
    enc_text = text.encode('utf-8')
    signature = 'ab' + hashlib.sha1(enc_text).hexdigest()
    print(f'Signature: {signature}')
    return signature


#AES加密部分
class AESCipher:
    """ this class used to encrypt and decrypt something with AES(ECB mode)...
    
    Args:
        key: string set on server, and length must be 16
    """
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        BS = 16
        # 这里必须是len(s.encode('utf-8'))，一开始直接用len(s)加密中文会报错，因为utf8编码里中文和英文长度不一样
        pad = lambda s: s + (BS - len(s.encode('utf-8')) % BS) * chr(BS - len(s.encode('utf-8')) % BS) 
        raw = pad(raw)
        cipher = AES.new( self.key, AES.MODE_ECB )
        enc_text = cipher.encrypt(raw).hex()
        return enc_text

    def decrypt(self, enc):
        unpad = lambda s : s[:-ord(s[len(s)-1:])]
        enc = bytes.fromhex(enc)
        cipher = AES.new(self.key, AES.MODE_ECB )
        dec_text = unpad(cipher.decrypt(enc)).decode()
        return dec_text

