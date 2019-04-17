# -*- coding:utf-8 -*-
import json, time, uuid, os
import requests
from secure import AESCipher, generateSign
from setToken import getToken

username = 'laijianhua'
password = 'LJHljh123'
uno = '200563'
encrypted = '0'
dsign = '0'
token_url = 'http://yz.geotmt.com/civp/getview/api/o/login'
data_url = 'http://yz.geotmt.com/civp/getview/api/u/queryUnify'
encryptKey = '1234567890123456'

#授权码部分
def genAuthcode(uno):
    timeStamp = str(int(time.time()))
    randomStr = str(uuid.uuid1()).replace('-','')
    authCode = timeStamp + '00' + uno + randomStr
    return authCode

def readPara(filename):
    if not os.path.isfile(filename):
        os.mknod(filename)
    with open(filename, 'r') as f:
        para = f.read()
    return para

def updateToken(username, password, uno, encrypted, dsign, token_url, encryptKey):
    getToken(username, password, uno, encrypted, dsign, token_url, encryptKey)
    print('Token update successfully!')

# 使用这个demo，如果请求其他接口，则入参可能有变化，需要对相关部分做增减
# 如果不加密调用，修改下面getData函数开头的几个全局变量和reqParam，共2部分
# 如果加密调用，修改下面getData函数开头的几个全局变量、reqParam、参数加密部分和ereqParam，共4部分
def getData():
    authCode = genAuthcode(uno)
    tokenId = readPara('token.txt')
    innerIfType = 'B7'
    cid = '13262861990' 
    idNumber = '110223199401040567'
    realName = '章贵'
    if not tokenId:
        getToken(username, password, uno, encrypted, dsign, token_url, encryptKey)
        tokenId = readPara('token.txt')

    reqParam = {'authCode':authCode,
                'tokenId':tokenId,
                'innerIfType':innerIfType,
                'cid':cid,
                'idNumber':idNumber,
                'realName':realName}

    if encrypted== '0':
        if dsign == '0':
            print('Start to get data!')
            reqData = requests.get(data_url, params=reqParam)
        elif dsign == '1':
            dsignKey = readPara('signature.txt')
            if not dsignKey:
                getToken(username, password, uno, encrypted, dsign, token_url, encryptKey)
                dsignKey = readPara('signature.txt')
            digitalSignature = generateSign(dsignKey, reqParam)
            headers = {'digitalSignature': digitalSignature}
            print('Start to get data!')
            reqData = requests.get(data_url, headers =headers, params =reqParam)
        reqText = reqData.text

    elif encrypted== '1':
        cipher = AESCipher(encryptKey)
        eauthCode = cipher.encrypt(authCode)
        einnerIfType = cipher.encrypt(innerIfType)
        ecid = cipher.encrypt(cid)
        eidNumber = cipher.encrypt(idNumber)
        erealName = cipher.encrypt(realName)
        ereqParam = {'authCode':eauthCode,
                    'tokenId':tokenId,
                    'cid':ecid,
                    'innerIfType':einnerIfType,
                    'idNumber':eidNumber,
                    'realName':erealName}
        if dsign == '0':
            print('Start to get data!')
            reqData = requests.get(data_url, params =ereqParam)
        elif dsign == '1':
            dsignKey = readPara('signature.txt')
            if not dsignKey:
                getToken(username, password, uno, encrypted, dsign, token_url, encryptKey)
                dsignKey = readPara('signature.txt')
            digitalSignature = generateSign(dsignKey, reqParam) #签名入参用的还是encrypted == 0时候的参数，该优化
            headers = {'digitalSignature': digitalSignature}
            print('Start to get data!')
            reqData = requests.get(data_url, headers =headers, params =ereqParam)
        reqText = cipher.decrypt(reqData.text)

    reqUrl = reqData.url
    print(f'Data Request URL:\n {reqUrl}')
    return reqText

def main():
    data = getData()
    code = json.loads(data)['code']
    if code == "-100" or code == "-200" or code == "-300" or code == "-301":
        getToken(username, password, uno, encrypted, dsign, token_url, encryptKey)
        data = getData().text
    print('数据接口请求结果：')
    print(data)

if __name__ == '__main__':
    main()
