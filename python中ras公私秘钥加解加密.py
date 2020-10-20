import requests
import datetime
import json
import rsa,urllib.parse
from base64 import b64encode, b64decode
def create_keys():
    """
    生成公钥和私钥
    :return:
    """
    (pubkey, privkey) = rsa.newkeys(1024)
    pub = pubkey.save_pkcs1()
    with open('public.pem','wb+')as f:
        f.write(pub)

    pri = privkey.save_pkcs1()
    with open('private.pem','wb+')as f:
        f.write(pri)

def encrypt(text):
    """
    用公钥加密
    :param text:需要加密的内容
    :return:加密结果
    """
    with open('应用公钥1024.pem', 'rb') as publickfile:
        p= publickfile.read()
        publickfile.close()
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(p)
    original_text = text.encode('utf8')
    length = len(original_text)
    default_length = 117
    res = []
    for i in range(0, length, default_length):
        res.append(rsa.encrypt(original_text[i:i + default_length],pubkey))
    byte_data = b''.join(res)
    print(byte_data)
    print(b64encode(byte_data).decode(encoding='utf-8'))
    return b64encode(byte_data).decode(encoding='utf-8') # 加密后的密文


def decrypt(crypt_text):
    """
    用私钥解密
    :param crypt_text:需要解密的内容
    :return:解密结果
    """
    with open('private.pem', 'rb') as privatefile:
        p = privatefile.read()
        privatefile.close()
    privkey = rsa.PrivateKey.load_pkcs1(p)
    length = len(crypt_text)
    default_length = 128
    res = []
    for i in range(0, length, default_length):
        res.append(rsa.decrypt(crypt_text[i:i + default_length], privkey))
    print(str(b''.join(res), encoding = "utf-8"))
    return str(b''.join(res), encoding="utf-8")

def rsa_sign(content):
    """
    私钥签名
    :param content:
    :return:
    """
    with open('private.pem', 'rb') as privatefile:
        p = privatefile.read()
        privatefile.close()
    privkey = rsa.PrivateKey.load_pkcs1(p)
    content = content.encode('utf-8')
    signature = rsa.sign(content, privkey,'SHA-1')  # 签名SHA-1/MD5
    return b64encode(signature).decode(encoding='utf-8')
    print("签名："+b64encode(signature).decode(encoding='utf-8'))

def rsa_verify(content,signature):
    """
    公钥验签
    :param content:需要验签的内容
    :param signature:签名字符串
    :return:
    """
    with open('应用公钥1024.pem', 'rb') as publickfile:
        p= publickfile.read()
        publickfile.close()
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(p)
    content = content.encode('utf-8')
    result = rsa.verify(content, signature, pubkey)  # 验签，失败抛出异常
    if(result):
        print("验证签名成功"+result)







if __name__ == '__main__':
    pass