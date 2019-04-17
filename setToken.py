import os
import requests
import json
from secure import AESCipher

#获取token, 无论什么情况，uno、encrypted都不加密
def getToken(username, password, uno, encrypted, dsign, token_url, encryptKey):
    print('Start to get token!')
    if encrypted == '0':
        paraDic = {'username':username, 'password':password, 'uno':uno, 'encrypted':encrypted, 'dsign':dsign}
        tokenRes = requests.get(token_url, params=paraDic)
        code = json.loads(tokenRes.text)['code']
        if code != '200':
            print('Fail to get token!')
            print('Responce From Server:', tokenRes.text)

        tokenData = json.loads(tokenRes.text)['data']
        tokenId = tokenData['tokenId']
        if dsign == '1':
            dsignKey = tokenData['digitalSignatureKey']
            with open('signature.txt', 'w') as f:
                f.write(dsignKey)        

    elif encrypted == '1':
        cipher = AESCipher(encryptKey)
        eUsername = cipher.encrypt(username)
        ePassword = cipher.encrypt(password)
        eDsign =  cipher.encrypt(dsign)
        paraDic = {'username':eUsername, 'password':ePassword, 'uno':uno, 'encrypted':encrypted, 'dsign':eDsign}
        tokenRes = requests.get(token_url, params=paraDic)
#        print(tokenRes.text) #返回的是密文，要解密一下
        plainTokenRes = cipher.decrypt(tokenRes.text)
        code = json.loads(plainTokenRes)['code']
        if code != '200':
            print('Fail to get token!')
            print('Responce From Server:', plainTokenRes)
            
        tokenData = json.loads(plainTokenRes)['data']
        tokenId = tokenData['tokenId']
        if dsign == '1':
            dsignKey = tokenData['digitalSignatureKey']
            with open('signature.txt', 'w') as f:
                f.write(dsignKey)        
    
    with open('token.txt', 'w') as f:
        f.write(tokenId)

