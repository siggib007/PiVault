# pip install pycryptodome
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

def encrypt(strkey, strData, encode=True):
    bKey = bytes(strkey,"UTF-8")
    bData = bytes(strData,"UTF-8")
    hKey = SHA256.new(bKey).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    objEncryptor = AES.new(hKey, AES.MODE_CBC, IV)
    iPadLen = AES.block_size - len(bData) % AES.block_size  # calculate needed padding
    bData += bytes([iPadLen]) * iPadLen  
    oEncrypted = IV + objEncryptor.encrypt(bData)  # store the IV at the beginning and encrypt
    return base64.b64encode(oEncrypted).decode("UTF-8") if encode else oEncrypted

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("UTF-8"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; 
    if data[-padding:] != bytes([padding]) * padding:  
        raise ValueError("Invalid padding...")
    bdecr = data[:-padding]  # remove the padding
    return bdecr.decode("UTF-8")


strPWD = "secret_AES_key_string_to_encrypt/decrypt_with"
my_password = bytes(strPWD, "UTF-8")
strTopSecret = "input string to encrypt and decrypt, very top secret stuff!!!"

print("key:  {}".format(strPWD))
print("data: {}".format(strTopSecret))
encrypted = encrypt(strPWD, strTopSecret)
print("\nenc:  {}".format(encrypted))
decrypted = decrypt(my_password, encrypted)
print("dec:  {}".format(decrypted))
print("\ndata match: {}".format(strTopSecret == decrypted))
print("\nSecond round....")
encrypted = encrypt(strPWD, strTopSecret)
print("\nenc:  {}".format(encrypted))
decrypted = decrypt(my_password, encrypted)
print("dec:  {}".format(decrypted))
print("\ndata match: {}".format(strTopSecret == decrypted))
