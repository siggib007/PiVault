'''
Very simply password vault. 
 - Takes in a string, encrypts it and stores the encryption.
 - Then retrieves the encrypted string and decrypts it for use

Author Siggi Bjarnason AUG 2022
Copyright 2022

Encrypt/decrypt functions copied from https://stackoverflow.com/a/44212550/8549454

Following packages need to be installed
pip install pycryptodome

'''
# Import libraries
import os
import csv
import time
import platform
import sys
import subprocess
import base64
try:
  from Crypto.Cipher import AES
  from Crypto.Hash import SHA256
  from Crypto import Random
except ImportError:
  subprocess.check_call(
      [sys.executable, "-m", "pip", "install", 'pycryptodome'])
finally:
  from Crypto.Cipher import AES
  from Crypto.Hash import SHA256
  from Crypto import Random

# End imports


def encrypt(strkey, strData, encode=True):
  """
  This handles encrypting a string using AES 
  Parameters:
    strkey: Simple string with encryption password
    strData: Simple string with the data to be encrypted
    encode: Optional, defaults to true. A boolean to indicate the return should be Base64 encoded.
  Returns:
    Encrypted string, either raw or base64 encoded depending on the encode parameter
  """
  bKey = bytes(strkey, "UTF-8")
  bData = bytes(strData, "UTF-8")
  # use SHA-256 over our key to get a proper-sized AES key
  hKey = SHA256.new(bKey).digest()
  IV = Random.new().read(AES.block_size)  # generate IV
  objEncryptor = AES.new(hKey, AES.MODE_CBC, IV)
  # calculate needed padding
  iPadLen = AES.block_size - len(bData) % AES.block_size
  bData += bytes([iPadLen]) * iPadLen
  # store the IV at the beginning and encrypt
  oEncrypted = IV + objEncryptor.encrypt(bData)
  return base64.b64encode(oEncrypted).decode("UTF-8") if encode else oEncrypted


def decrypt(strkey, strData, decode=True):
  """
  This handles decrypting a string encrypted with AES 
  Parameters:
    strkey: Simple string with encryption password
    strData: Simple string with the encrypted data
    encode: Optional, defaults to true. A boolean to indicate if the data is Base64 encoded.
  Returns:
    Decrypted clear text simple string
  """
  if decode:
      strData = base64.b64decode(strData.encode("UTF-8"))
  bKey = bytes(strkey, "UTF-8")
  hKey = SHA256.new(bKey).digest()
  IV = strData[:AES.block_size]  # extract the IV from the beginning
  objEncryptor = AES.new(hKey, AES.MODE_CBC, IV)
  bClear = objEncryptor.decrypt(strData[AES.block_size:])  # decrypt
  iPadLen = bClear[-1]  # pick the padding value from the end;
  if bClear[-iPadLen:] != bytes([iPadLen]) * iPadLen:
      raise ValueError("Invalid padding...")
  bClear = bClear[:-iPadLen]  # remove the padding
  return bClear.decode("UTF-8")


def main():
  lstSysArg = sys.argv

  strBaseDir = os.path.dirname(sys.argv[0])
  strRealPath = os.path.realpath(sys.argv[0])
  strRealPath = strRealPath.replace("\\", "/")
  if strBaseDir == "":
    iLoc = strRealPath.rfind("/")
    strBaseDir = strRealPath[:iLoc]
  if strBaseDir[-1:] != "/":
    strBaseDir += "/"
  strScriptName = os.path.basename(sys.argv[0])
  strVersion = "{0}.{1}.{2}".format(
      sys.version_info[0], sys.version_info[1], sys.version_info[2])
  strScriptHost = platform.node().upper()

  print("This is a simple password vault script. Enter in a key value pair and the value will be encrypted with AES and stored under the key."
        "This is running under Python Version {}".format(strVersion))
  print("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print("The time now is {}".format(dtNow))
  if os.getenv("VAULT") != "" and os.getenv("VAULT") is not None:
    strVAULT = os.getenv("VAULT")
  else:
    print("no VAULT environment valuable")


if __name__ == '__main__':
    main()
