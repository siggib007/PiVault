'''
Very simply password vault. 
 - Takes in a string, encrypts it and stores the encryption.
 - Then retrieves the encrypted string and decrypts it for use

Author Siggi Bjarnason AUG 2022
Copyright 2022

Encrypt/decrypt functions copied from https://stackoverflow.com/a/44212550/8549454

Following packages need to be installed
pip install pycryptodome
pip install maskpass

'''
# Import libraries
import os
import time
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
try:
  import maskpass
except ImportError:
  subprocess.check_call(
      [sys.executable, "-m", "pip", "install", 'maskpass'])
finally:
  import maskpass

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
  bData = bytes(strData, "UTF-8")  # use SHA-256 over our key to get a proper-sized AES key
  hKey = SHA256.new(bKey).digest()
  IV = Random.new().read(AES.block_size)  # generate IV
  objEncryptor = AES.new(hKey, AES.MODE_CBC, IV)  # calculate needed padding
  iPadLen = AES.block_size - len(bData) % AES.block_size
  bData += bytes([iPadLen]) * iPadLen  # store the IV at the beginning and encrypt
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


def OpenFile(strFileName, strperm):
  try:
    objFileOut = open(strFileName, strperm, encoding='utf8')
    return objFileOut
  except PermissionError:
    print("unable to open output file {} for writing, "
              "permission denied.".format(strFileName))
    return("Permission denied")
  except FileNotFoundError:
    print("unable to open output file {} for writing, "
              "Issue with the path".format(strFileName))
    return("file not found")

def DefineMenu():
  global dictMenu

  dictMenu = {}
  dictMenu["help"] = "Displays this message. Can also use /h -h and --help"
  dictMenu["quit"] = "exit out of the script"
  dictMenu["add"] = "Adds a new key value pair"
  dictMenu["list"] = "List out all keys"
  dictMenu["fetch"] = "fetch a specified key"


def DisplayHelp():
  print("\nHere are the commands you can use:")
  for strItem in dictMenu:
    if len(lstVault) > 1:
      print("{} : {}".format(strItem, dictMenu[strItem]))
    elif strItem != "list" and strItem != "fetch":
      print("{} : {}".format(strItem, dictMenu[strItem]))

def ProcessCMD(strCmd):
  global bCont
  strCmd = strCmd.replace("-", "")
  strCmd = strCmd.replace("/", "")
  strCmd = strCmd.replace("\\", "")
  strCmd = strCmd.replace("<", "")
  strCmd = strCmd.replace(">", "")
  strCmd = strCmd.lower()
  if strCmd == "q" or strCmd == "quit" or strCmd == "exit":
    bCont = False
    print("Goodbye!!!")
    return
  if strCmd == "h":
    strCmd = "help"
  if strCmd not in dictMenu:
    print("command {} not valid".format(strCmd))
    return
  if strCmd == "help":
    DisplayHelp()
  else:
    print("Not implemented")

def main():

  global bCont
  global lstVault
  DefineMenu()
  lstSysArg = sys.argv

  strBaseDir = os.path.dirname(sys.argv[0])
  strRealPath = os.path.realpath(sys.argv[0])
  strRealPath = strRealPath.replace("\\", "/")
  if strBaseDir == "":
    iLoc = strRealPath.rfind("/")
    strBaseDir = strRealPath[:iLoc]
  if strBaseDir[-1:] != "/":
    strBaseDir += "/"
  strVersion = "{0}.{1}.{2}".format(
      sys.version_info[0], sys.version_info[1], sys.version_info[2])

  print("This is a simple password vault script. Enter in a key value pair and the value will be encrypted with AES and stored under the key."
        "This is running under Python Version {}".format(strVersion))
  print("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  print("The time now is {}".format(dtNow))
  if os.getenv("VAULT") != "" and os.getenv("VAULT") is not None:
    strVault = os.getenv("VAULT")
  else:
    print("no vault environment valuable")

  if len(lstSysArg) > 1:
    if lstSysArg[1][:5].lower() == "vault":
      strVault = lstSysArg[1][6:]
      print("Using vault from argument: {}".format(strVault))
    else:
      strVault = ""
  else:
    strVault = ""
  if strVault == "":
    strVault = strBaseDir + "PieVaultData/"

  print("No vault path provided in either env or argument. Defaulting vault path to: {}".format(strVault))
  if not os.path.exists(strVault):
    os.makedirs(strVault)
    print(
        "\nPath '{0}' for vault didn't exists, so I create it!\n".format(strVault))

  strCheckValue = "This is a simple password vault"
  bCont = False
  lstVault = os.listdir(strVault)
  if len(lstVault) == 0:
    strPWD = maskpass.askpass(prompt="Please provide vault password: ",mask="*")
    strFileOut = strVault + "VaultInit.txt"
    tmpResponse = OpenFile(strFileOut, "w")
    if isinstance(tmpResponse, str):
      print(tmpResponse)
    else:
      objFileOut = tmpResponse
    objFileOut.write(encrypt(strPWD, strCheckValue))
    print("Vault Initialized")
    objFileOut.close()
    bCont = True
  else:
    print("Vault is initialized and contains {} entries".format(len(lstVault)-1))
    if "VaultInit.txt" in lstVault:
      strPWD = maskpass.askpass(
          prompt="Please provide vault password: ", mask="*")
      strFileIn = strVault + "VaultInit.txt"
      tmpResponse = OpenFile(strFileIn, "r")
      if isinstance(tmpResponse, str):
        print(tmpResponse)
      else:
        objFileIn = tmpResponse
        strValue = objFileIn.read()
        try:
          if decrypt(strPWD, strValue) == strCheckValue:
            print("Password is good")
            bCont = True
          else:
            print("unable to decrypt vault")
        except ValueError:
          print("Failed to decrypt the vault")
  while bCont:
    DisplayHelp()
    strCmd = input("Please enter a command: ")
    ProcessCMD(strCmd)




if __name__ == '__main__':
    main()
