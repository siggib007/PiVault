'''
Very simply secrets vault.
 - Takes in a string, encrypts it and stores the encrypted string.
 - Then retrieves the encrypted string and decrypts it for use

Author Siggi Bjarnason AUG 2022
Copyright 2022

Encrypt/decrypt functions copied from https://stackoverflow.com/a/44212550/8549454

Following packages need to be installed for base functionality
pip install pycryptodome
pip install maskpass

If you want to use clipboard feature
pip install pyperclip

If you are using Redis also:
pip install redis

If you are using TOTP feature
pip install pyotp
'''
# Import libraries
import os
import shutil
import time
import sys
import subprocess
import base64
import re


# Global constants
iDefShowTime = 30    # Default time show password in GUI
bDefAutoHide = True  # Default to auto hide password after show time expires
bDefHide = False     # Default hide password while typing
strDefValueColor = "red"
strDefStore = "files"
strDefVault = "VaultData"
strDefTable = "tblVault"
strCheckValue = "This is a simple secrets vault"
strCheckKey = "VaultInit"
lstDBTypes = ["sqlite", "mysql", "postgres", "mssql"]
lstStoreTypes = ["files","redis"]
bLoggedIn = False
dictComponents = {}
iTimer = 0
strICOFile = "PieLock.ico"

#functions

def CheckDependency(Module):
  """
  Function that installs missing depedencies
  Parameters:
    Module : The name of the module that should be installed
  Returns:
    dictionary object without output from the installation.
      if the module needed to be installed
        code: Return code from the installation
        stdout: output from the installation
        stderr: errors from the installation
        args: list object with the arguments used during installation
        success: true/false boolean indicating success.
      if module was already installed so no action was taken
        code: -5
        stdout: Simple String: {module} version {x.y.z} already installed
        stderr: Nonetype
        args: module name as passed in
        success: True as a boolean
  """
  global dictComponents

  dictReturn = {}
  strModule = Module
  if len(dictComponents) == 0:
    lstOutput = subprocess.run(
      [sys.executable, "-m", "pip", "list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lstLines = lstOutput.stdout.decode("utf-8").splitlines()
    for strLine in lstLines:
      lstParts = strLine.split()
      dictComponents[lstParts[0].lower()] = lstParts[1]

  if strModule.lower() not in dictComponents:
    lstOutput = subprocess.run(
        [sys.executable, "-m", "pip", "install", strModule], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    dictReturn["code"] = lstOutput.returncode
    dictReturn["stdout"] = lstOutput.stdout.decode("utf-8")
    dictReturn["stderr"] = lstOutput.stderr.decode("utf-8")
    dictReturn["args"] = lstOutput.args
    if lstOutput.returncode == 0:
      dictReturn["success"] = True
    else:
      dictReturn["success"] = False
    return dictReturn
  else:
    dictReturn["code"] = -5
    dictReturn["stdout"] = "{} version {} already installed".format(
        strModule, dictComponents[strModule.lower()])
    dictReturn["stderr"] = None
    dictReturn["args"] = strModule
    dictReturn["success"] = True
    return dictReturn

if not CheckDependency("pycryptodome")["success"]:
  print("failed to install pycryptodome. Please pip install pycryptodome as that is needed for all the crypto work.")
  sys.exit(5)

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

if not CheckDependency("maskpass")["success"]:
  print("failed to install maskpass. Please pip install maskpass to be able to mask the password input.")
  sys.exit(5)

import maskpass

# End imports

def ShowGUI():
  """
  Function that handles the whole GUI. All GUI functions and code are here
  Parameters:
    nothing
  Returns:
    nothing
  """
  global iTimer

  import os
  try:
    import tkinter as tk
    from tkinter import messagebox as mb
  except ImportError:
    print("unable to start GUI")
    return

  def Config():
    """
    Part of ShowGUI. Function that handles the Preferences Config Window
    Parameters:
      nothing
    Returns:
      nothing
    """
    global iClippy
    global iHideIn
    global strStoreType
    global iTOTP
    global strColor
    global objVaultText
    global objConfWin
    global objVaultLbl
    global objVaultText
    global objHostLbl
    global objHostText
    global objPortLbl
    global objPortText
    global objTableLbl
    global objTableText
    global objDatabaseLbl
    global objDatabaseText
    global objDBUserLbl
    global objDBUserText
    global objDBPassLbl
    global objDBPassText
    global objNoteLbl


    lstStoreOptions = lstStoreTypes.copy()
    lstStoreOptions += lstDBTypes.copy()
    objConfWin = tk.Toplevel(objMainWin)
    iWidth = 600
    iHeight = 450
    ixMargin = 50
    iyMargin = 50
    iScreenW = objConfWin.winfo_screenwidth()
    iScreenH = objConfWin.winfo_screenheight()
    ixMargin = int(iScreenW/2 - iWidth/2)
    iyMargin = int(iScreenH/2 - iHeight/2)
    objConfWin.resizable(width=False, height=False)
    objConfWin.geometry(
        "{}x{}+{}+{}".format(iWidth, iHeight, ixMargin, iyMargin))

    objConfWin.title("Configuration")
    objConfWin.iconbitmap(strICOFile)
    objConfWin.columnconfigure(0, weight=1)
    objConfWin.columnconfigure(3, weight=1)
    objConfLbl = tk.Label(objConfWin,text="PiVault Configuration")
    objConfLbl.grid(row=0, columnspan=5, sticky=tk.EW, padx=10,pady=10)
    objConfLbl.config(font=("arial bold",24))
    objStoreLbl = tk.Label(objConfWin,text="Store Type: ")
    objStoreLbl.grid(row=1, column=1, sticky=tk.E)
    strStoreType = tk.StringVar()
    strStoreType.set(strStore)
    cmbStore = tk.OptionMenu(objConfWin, strStoreType, *lstStoreOptions, command=UpdateView)
    cmbStore.grid(row=1,column=2,sticky=tk.W)

    objVaultLbl = tk.Label(objConfWin,text="Vault: ")
    objVaultLbl.grid(row=2, column=1, sticky=tk.E)
    objVaultText = tk.Entry(objConfWin,width=50)
    objVaultText.grid(row=2, column=2)
    objVaultText.insert(0,strVault)

    objHostLbl = tk.Label(objConfWin, text="Host: ")
    objHostLbl.grid(row=3, column=1, sticky=tk.E)
    objHostText = tk.Entry(objConfWin, width=50)
    objHostText.grid(row=3, column=2)
    objHostText.insert(0, FetchEnv("HOST"))

    objPortLbl = tk.Label(objConfWin, text="Port: ")
    objPortLbl.grid(row=4, column=1, sticky=tk.E)
    objPortText = tk.Entry(objConfWin, width=50)
    objPortText.grid(row=4, column=2)
    objPortText.insert(0, FetchEnv("PORT"))

    strTable = FetchEnv("TABLE")
    if strTable == "":
      strTable = strDefTable
    objTableLbl = tk.Label(objConfWin, text="Table: ")
    objTableLbl.grid(row=5, column=1, sticky=tk.E)
    objTableText = tk.Entry(objConfWin, width=50)
    objTableText.grid(row=5, column=2)
    objTableText.insert(0, strTable)

    objDatabaseLbl = tk.Label(objConfWin, text="Database: ")
    objDatabaseLbl.grid(row=6, column=1, sticky=tk.E)
    objDatabaseText = tk.Entry(objConfWin, width=50)
    objDatabaseText.grid(row=6, column=2)
    objDatabaseText.insert(0, FetchEnv("DB"))

    objDBUserLbl = tk.Label(objConfWin, text="Database User: ")
    objDBUserLbl.grid(row=7, column=1, sticky=tk.E)
    objDBUserText = tk.Entry(objConfWin, width=50)
    objDBUserText.grid(row=7, column=2)
    objDBUserText.insert(0, FetchEnv("DBUSER"))

    objDBPassLbl = tk.Label(objConfWin, text="DB Password: ")
    objDBPassLbl.grid(row=8, column=1, sticky=tk.E)
    objDBPassText = tk.Entry(objConfWin, width=50)
    objDBPassText.grid(row=8, column=2)
    objDBPassText.insert(0, FetchEnv("DBPWD"))

    objNoteLbl = tk.Label(
        objConfWin, text="Don't Use, use Env Var instead", fg="red")
    objNoteLbl.grid(row=8, column=3, padx=5, sticky=tk.W)

    iHideIn = tk.IntVar()
    objHideInLbl = tk.Label(objConfWin, text="Hide Input: ")
    objHideInLbl.grid(row=9, column=1, sticky=tk.E)
    objHideInChk = tk.Checkbutton(objConfWin, variable=iHideIn)
    objHideInChk.grid(row=9, column=2, sticky=tk.W)
    if bHideValueIn:
      objHideInChk.select()

    objSectionLbl = tk.Label(objConfWin,text="The following only impacts CLI")
    objSectionLbl.grid(row=10, columnspan=5, sticky=tk.EW, padx=10, pady=10)
    objSectionLbl.config(font=("arial bold", 14))

    strValueColor = FetchEnv("VALUECOLOR")
    if strValueColor == "":
      strValueColor = strDefValueColor

    objColorLbl = tk.Label(objConfWin, text="Value Color: ")
    objColorLbl.grid(row=11, column=1, sticky=tk.E)
    strColor = tk.StringVar()
    strColor.set(strValueColor)
    cmbColor = tk.OptionMenu(objConfWin, strColor,*dictColor.keys())
    cmbColor.grid(row=11, column=2, sticky=tk.W)

    iTOTP = tk.IntVar()
    objTOTPLbl = tk.Label(objConfWin, text="Enable TOTP: ")
    objTOTPLbl.grid(row=12, column=1, sticky=tk.E)
    objTOTPChk = tk.Checkbutton(objConfWin,variable=iTOTP)
    objTOTPChk.grid(row=12, column=2, sticky=tk.W)
    if bTOTP:
      objTOTPChk.select()

    iClippy = tk.IntVar()
    objClippyLbl = tk.Label(objConfWin, text="Enable Clippy: ")
    objClippyLbl.grid(row=13, column=1, sticky=tk.E)
    objClippyChk = tk.Checkbutton(objConfWin,variable=iClippy)
    objClippyChk.grid(row=13, column=2, sticky=tk.W)
    if bClippy:
      objClippyChk.select()

    btnSave = tk.Button(objConfWin, text="Save", width=15,
                          height=1, command=SaveConfig)
    btnSave.grid(row=14, columnspan=5, padx=10, pady=10)
    UpdateView(strStore)

  def SaveConfig():
    """
    Part of ShowGUI. Function that handles collecting data from Preference window
    and passing it onto the create config file function in the main code
    Parameters:
      nothing
    Returns:
      nothing
    """

    dictConfFile = {}
    if iClippy.get() == 1:
      dictConfFile["CLIPPYENABLE"] = "true"
    else:
      dictConfFile["CLIPPYENABLE"] = "false"
    if iHideIn.get() == 1:
      dictConfFile["HIDEINPUT"] = "true"
    else:
      dictConfFile["HIDEINPUT"] = "false"
    if iTOTP.get() == 1:
      dictConfFile["TOTPENABLE"] = FetchEnv("TOTPENABLE")
    dictConfFile["DB"] = objDatabaseText.get()
    dictConfFile["DBPWD"] = objDBPassText.get()
    dictConfFile["DBUSER"] = objDBUserText.get()
    dictConfFile["HOST"] = objHostText.get()
    dictConfFile["PORT"] = objPortText.get()
    dictConfFile["STORE"] = strStoreType.get()
    dictConfFile["TABLE"] = objTableText.get()
    dictConfFile["VALUECOLOR"] = strColor.get()
    dictConfFile["VAULT"] = objVaultText.get()
    CreateConfig(dictConfFile)
    objConfWin.destroy()

  def UpdateView(strTemp):
    """
    Part of ShowGUI. Function that handles making the Preferences Config Window
    dynamic based on what is selected in the Store dropdown box.
    Parameters:
      strTemp: String indicating the value selected
    Returns:
      nothing
    """

    if strTemp == "files":
      objVaultLbl.grid(row=2, column=1, sticky=tk.E)
      objVaultText.grid(row=2, column=2)
      objHostLbl.grid_remove()
      objHostText.grid_remove()
      objPortLbl.grid_remove()
      objPortText.grid_remove()
      objTableLbl.grid_remove()
      objTableText.grid_remove()
      objDatabaseLbl.grid_remove()
      objDatabaseText.grid_remove()
      objDBUserLbl.grid_remove()
      objDBUserText.grid_remove()
      objDBPassLbl.grid_remove()
      objDBPassText.grid_remove()
      objNoteLbl.grid_remove()
    elif strTemp == "redis":
      objVaultLbl.grid_remove()
      objVaultText.grid_remove()
      objHostLbl.grid(row=3, column=1, sticky=tk.E)
      objHostText.grid(row=3, column=2)
      objPortLbl.grid(row=4, column=1, sticky=tk.E)
      objPortText.grid(row=4, column=2)
      objTableLbl.grid_remove()
      objTableText.grid_remove()
      objDatabaseLbl.grid(row=6, column=1, sticky=tk.E)
      objDatabaseText.grid(row=6, column=2)
      objDBUserLbl.grid(row=7, column=1, sticky=tk.E)
      objDBUserText.grid(row=7, column=2)
      objDBPassLbl.grid(row=8, column=1, sticky=tk.E)
      objDBPassText.grid(row=8, column=2)
      objNoteLbl.grid(row=8, column=3, padx=5, sticky=tk.W)
    elif strTemp == "sqlite":
      objVaultLbl.grid(row=2, column=1, sticky=tk.E)
      objVaultText.grid(row=2, column=2)
      objHostLbl.grid_remove()
      objHostText.grid_remove()
      objPortLbl.grid_remove()
      objPortText.grid_remove()
      objTableLbl.grid(row=5, column=1, sticky=tk.E)
      objTableText.grid(row=5, column=2)
      objDatabaseLbl.grid_remove()
      objDatabaseText.grid_remove()
      objDBUserLbl.grid_remove()
      objDBUserText.grid_remove()
      objDBPassLbl.grid_remove()
      objDBPassText.grid_remove()
      objNoteLbl.grid_remove()
    elif strTemp in lstDBTypes:
      objVaultLbl.grid_remove()
      objVaultText.grid_remove()
      objHostLbl.grid(row=3, column=1, sticky=tk.E)
      objHostText.grid(row=3, column=2)
      objPortLbl.grid_remove()
      objPortText.grid_remove()
      objTableLbl.grid(row=5, column=1, sticky=tk.E)
      objTableText.grid(row=5, column=2)
      objDatabaseLbl.grid(row=6, column=1, sticky=tk.E)
      objDatabaseText.grid(row=6, column=2)
      objDBUserLbl.grid(row=7, column=1, sticky=tk.E)
      objDBUserText.grid(row=7, column=2)
      objDBPassLbl.grid(row=8, column=1, sticky=tk.E)
      objDBPassText.grid(row=8, column=2)
      objNoteLbl.grid(row=8, column=3, padx=5, sticky=tk.W)
    else:
      objVaultLbl.grid(row=2, column=1, sticky=tk.E)
      objVaultText.grid(row=2, column=2)
      objHostLbl.grid(row=3, column=1, sticky=tk.E)
      objHostText.grid(row=3, column=2)
      objPortLbl.grid(row=4, column=1, sticky=tk.E)
      objPortText.grid(row=4, column=2)
      objTableLbl.grid(row=5, column=1, sticky=tk.E)
      objTableText.grid(row=5, column=2)
      objDatabaseLbl.grid(row=6, column=1, sticky=tk.E)
      objDatabaseText.grid(row=6, column=2)
      objDBUserLbl.grid(row=7, column=1, sticky=tk.E)
      objDBUserText.grid(row=7, column=2)
      objDBPassLbl.grid(row=8, column=1, sticky=tk.E)
      objDBPassText.grid(row=8, column=2)
      objNoteLbl.grid(row=8, column=3, padx=5, sticky=tk.W)

  def MyTimer():
    """
    Part of ShowGUI. Function that handles counting down in the gui
    Used by the show value to automatically hide the value after few seconds
    Parameters:
      nothing
    Returns:
      nothing
    """
    global iTimer

    iTimer -= 1
    objCountdown.grid(row=2, column=1)
    objCountdown.config(text="Auto hiding in {} seconds".format(iTimer))
    if iTimer < iShowTime/3:
      objCountdown.config(bg="pink", fg="black")
    if btnShow.cget("text") == "Hide":
      objMainWin.after(1000, MyTimer)
    else:
      objCountdown.config(text="", bg="lightgreen", fg="black")
      objCountdown.grid_remove()

  def Login():
    """
    Part of ShowGUI. Function that make login fields visible
    Parameters:
      nothing
    Returns:
      nothing
    """

    btnLogin.grid_remove
    objPWDNote.grid_remove()
    objPWDLabel.grid(row=0, column=6, padx=20)
    objPWDText.grid(row=1, column=6, padx=20)
    objPWDText.delete(0, tk.END)
    objPWDText.insert(0, strPWD)
    btnAuth.grid(row=2, column=6, padx=20)

  def Auth():
    """
    Part of ShowGUI. Function that collects the login info
    and passess it to the userlogin function in main code
    then hides the login fields if successful
    Parameters:
      nothing
    Returns:
      nothing
    """
    if objPWDText.get() == "":
      return
    objPWDLabel.grid_remove()
    objPWDText.grid_remove()
    btnAuth.grid_remove()
    if btnAuth.cget("text") == "Authenticate":
      global strPWD
      objPWDNote.grid(row=0, column=6)
      strPWD = objPWDText.get()
      if (UserLogin()):
        objPWDNote.config(bg="lightgreen", fg="black", text="Logged in")
      else:
        objPWDNote.config(bg="pink", fg="black", text="Invalid Password")
    elif btnAuth.cget("text") == "Change":
      if(ChangePWD(objPWDText.get())):
        strMsg = "Password change successful"
      else:
        strMsg = ("Password changed failed on {} of {} entries. "
        "The following keys failed {}".format(
            len(lstFailed), len(lstVault), (lstFailed)))
      objMsg1.config(text=strMsg)
      btnAuth.config(text="Authenticate")
      btnChgPwd.grid(row=3, column=6, padx=0)
      Auth()
    else:
      mb.showerror("Unexpected", "I have no idea how to deal with btnAuth having a text of {}".format(
          btnAuth.cget("text")))

  def CopyValue():
    """
    Part of ShowGUI. Function that fetches value, decrypts it and places it on the clipboard.
    Parameters:
      nothing
    Returns:
      nothing
    """
    lstSel = objItemsLB.curselection()
    if len(lstSel) > 0:
      strSel = objItemsLB.get(lstSel[0])
      strValue = FetchItem(strSel)
      objMainWin.clipboard_clear()
      objMainWin.clipboard_append(strValue)
    else:
      strMsg = "Please select a value"
      objMsg1.config(text=strMsg)

  def ShowValue():
    """
    Part of ShowGUI. Function that fetches value, decrypts it
    and writes it in the right field on the window.
    Parameters:
      nothing
    Returns:
      nothing
    """
    global iTimer
    global objHide

    if btnShow.cget("text") == "Show":
      lstSel = objItemsLB.curselection()
      if len(lstSel) > 0:
        strSel = objItemsLB.get(lstSel[0])
        strValue = FetchItem(strSel)
        if strValue == False:
          strValue = "Failed to fetch value"
        objValueText.delete(0, tk.END)
        objValueText.insert(0, strValue)
      else:
        strSel = "nothing"
      btnAdd.config(text="Update")
      btnShow.config(text="Hide")
      objKeyText.delete(0, tk.END)
      objKeyText.insert(0, strSel)
      objValueText.config(show="")
      if bAutoHide:
        iTimer = iShowTime
        objMainWin.after(1000, MyTimer)
        objHide = objMainWin.after(iShowTime*1000, ShowValue)
    else:
      objMsg1.config(text=strMsg)
      btnShow.config(text="Show")
      btnAdd.config(text="Add")
      objKeyText.delete(0, tk.END)
      objValueText.delete(0, tk.END)
      if bHideValueIn:
        objValueText.config(show="*")
      objCountdown.grid_remove()
      objMainWin.after_cancel(objHide)
      iTimer = 0

  def ShTOTP():
    """
    Part of ShowGUI. Function that fetches TOTP secret, decrypts it,
    calculated the TOTP number and writes it in the right field on the window.
    Parameters:
      nothing
    Returns:
      nothing
    """
    lstSel = objItemsLB.curselection()
    if len(lstSel) > 0:
      strSel = objItemsLB.get(lstSel[0])
    else:
      objCountdown.config(text="Please select a key!!")
      objCountdown.config(bg="pink", fg="black")
      objCountdown.grid(row=2, column=1)
      return
    strCode = ShowTOTP(strSel)
    objCountdown.grid(row=2, column=1)
    objCountdown.config(text="Your TOTP Code is: {}".format(strCode))
    objCountdown.config(bg="lightgreen", fg="black")
    objMainWin.clipboard_clear()
    objMainWin.clipboard_append(strCode)

    if bAutoHide:
      objMainWin.after(iShowTime*1000, ClearTOTP)

  def ClearTOTP():
    """
    Part of ShowGUI. Function that clears the TOTP value from the screen
    Parameters:
      nothing
    Returns:
      nothing
    """

    objCountdown.config(text="")
    objCountdown.grid_remove()

  def AddKey():
    """
    Part of ShowGUI. Function that collects new key details from the UI
    and passess it to the right functions in the main code.
    Parameters:
      nothing
    Returns:
      nothing
    """
    bCont = True
    bUpdate = False
    strKey = objKeyText.get()
    strValue = objValueText.get()
    if strKey in lstVault and btnAdd.cget("text") == "Add":
      strResp = mb.askquestion("Overwrite entry","key {} already exists. Overwrite it?".format(strKey))
      if strResp != "yes":
        bCont = False
        bUpdate = True
    if btnAdd.cget("text") == "Update" or strKey in lstVault:
      bUpdate= True
    if not bLoggedIn:
      bCont = False
      objMsg1.config(text="You are not logged in")
    if bCont:
      if AddItem(strKey, strValue, False):
        lstVault.append(strKey)
        strMsg ="key {} successfully created or updated".format(strKey)
        if not bUpdate:
          objItemsLB.insert(tk.END, strKey)
        strLBCount = "There are {} entries".format(objItemsLB.size())
        objLBMsg.config(text=strLBCount)
        objKeyText.delete(0, tk.END)
        objValueText.delete(0, tk.END)
      else:
        strMsg ="Failed to create key {}".format(strKey)
      objMsg1.config(text=strMsg)

  def ChgPWD():
    """
    Part of ShowGUI. Function that handles collecting new password
    and calls the right functions in the main code
    Parameters:
      nothing
    Returns:
      nothing
    """
    objPWDLabel.config(text="New Password")
    Login()
    objPWDText.delete(0, tk.END)
    btnAuth.config(text="Change")
    btnChgPwd.grid_remove()

  def ItemDel():
    """
    Part of ShowGUI. Function that deletes the selected value
    Parameters:
      nothing
    Returns:
      nothing
    """
    lstSel = objItemsLB.curselection()
    if len(lstSel) > 0:
      strSel = objItemsLB.get(lstSel[0])
      if (DelItem(strSel)):
        strMsg = "Deleted {} successfully".format(strSel)
        objItemsLB.delete(lstSel)
        strLBCount = "There are {} entries".format(objItemsLB.size())
        objLBMsg.config(text=strLBCount)
      else:
        strMsg = "Deleting {} failed".format(strSel)
    else:
      strMsg = "Please select a key to delete"
    objMsg1.config(text=strMsg)

  def DBWipe():
    """
    Part of ShowGUI. Function that wipes the current database clean
    Parameters:
      nothing
    Returns:
      nothing
    """
    strReponse = mb.askquestion(
        "Wipe the database", "Are you sure you want to completely nuke the database? \nTHIS ACTION IS IRREVERSABLE")
    if strReponse == "yes":
      ResetStore()
      objMainWin.destroy()

  def GUILayout():
    """
    Part of ShowGUI. Main window layout function
    Parameters:
      nothing
    Returns:
      nothing
    """

    global objMainWin
    global objCountdown
    global btnShow
    global btnLogin
    global objPWDNote
    global objPWDLabel
    global objPWDText
    global btnAuth
    global objItemsLB
    global objMsg1
    global objValueText
    global btnAdd
    global objKeyText
    global strMsg
    global objLBMsg
    global btnChgPwd


    objMainWin = tk.Tk()
    objMainWin.title("PiVault")
    iWidth = 670
    iHeight = 320
    ixMargin = 50
    iyMargin = 50
    iScreenW = objMainWin.winfo_screenwidth()
    iScreenH = objMainWin.winfo_screenheight()
    ixMargin = int(iScreenW/2 - iWidth/2)
    iyMargin = int(iScreenH/2 - iHeight/2)
    objMainWin.attributes("-alpha", 0.95)
    objMainWin.resizable(width=False, height=False)
    objMainWin.geometry(
        "{}x{}+{}+{}".format(iWidth, iHeight, ixMargin, iyMargin))

    objMenu = tk.Menu(objMainWin)
    objMainWin.config(menu=objMenu)
    objFileMenu = tk.Menu(objMenu,tearoff=False)
    objFileMenu.add_command(label="Preferences",command=Config)
    objFileMenu.add_separator()
    objFileMenu.add_command(label="Exit",command=objMainWin.destroy)
    objMenu.add_cascade(label="File", menu=objFileMenu)

    objDBmenu = tk.Menu(objMenu,tearoff=False)
    objDBmenu.add_command(label="Nuke the database",command=DBWipe)
    objMenu.add_cascade(label="DataBase",menu=objDBmenu)

    btnAdd = tk.Button(objMainWin, text="Add", width=8,
                      height=1, command=AddKey)
    btnAdd.grid(row=0, column=3, rowspan=2, padx=10)

    btnShow = tk.Button(objMainWin, text="Show", width=8,
                        height=1, command=ShowValue)
    btnShow.grid(row=2, column=3, padx=10)

    btnCopy = tk.Button(objMainWin, text="Copy", width=8,
                        height=1, command=CopyValue)
    btnCopy.grid(row=3, column=3, padx=10)

    btnTOTP = tk.Button(objMainWin, text="TOTP", width=8,
                        height=1, command=ShTOTP)
    btnTOTP.grid(row=4, column=3, padx=10)

    btnLogin = tk.Button(objMainWin, text="Login", width=8,
                        height=1, command=Login)
    btnLogin.grid(row=2, column=6, padx=45)

    btnAuth = tk.Button(objMainWin, text="Authenticate", width=10,
                        height=1, command=Auth)

    btnChgPwd = tk.Button(objMainWin, text="Change Password", width=15,
                          height=1, command=ChgPWD)
    btnChgPwd.grid(row=3, column=6, padx=0)

    btnDel = tk.Button(objMainWin, text="Delete", width=8,
                      height=1, command=ItemDel)
    btnDel.grid(row=5, column=3, padx=10)

    objPWDLabel = tk.Label(objMainWin, text="Please enter your password")
    objPWDText = tk.Entry(objMainWin, width=25, show="*")

    tk.Label(objMainWin, text="Key").grid(row=0, column=0, padx=10, sticky=tk.E)
    tk.Label(objMainWin, text="Value").grid(
        row=1, column=0, padx=10, sticky=tk.E)
    objKeyText = tk.Entry(objMainWin, width=50)
    objKeyText.grid(row=0, column=1)
    objValueText = tk.Entry(objMainWin, width=50)
    if bHideValueIn:
      objValueText.config(show="*")
    objValueText.grid(row=1, column=1)

    objSB_Items = tk.Scrollbar(objMainWin)
    objSB_Items.grid(row=3, column=2, rowspan=6, sticky=tk.NS)

    objItemsLB = tk.Listbox(objMainWin, yscrollcommand=objSB_Items.set, width=50)
    for strItem in lstVault:
      if strItem != strCheckKey:
        objItemsLB.insert(tk.END, strItem)

    objItemsLB.grid(row=3, column=1, rowspan=6)
    objSB_Items.config(command=objItemsLB.yview)

    strMsg = "Welcome to the PiVault GUI, a simple secrets vault encrytping with AES-256 using MODE_CBC"
    strMsg += "\nThis is running under Python Version {} ".format(strVersion)
    strMsg += "using {} ".format(strStore)
    if strStore != "files":
      strMsg += "on {}".format(FetchEnv("HOST"))
    objMsg1 = tk.Message(objMainWin, text=strMsg, width=iWidth-50)
    objMsg1.config(bg="lightblue", fg="black")
    objMsg1.place(x=20, y=iHeight - 50)

    objPWDNote = tk.Message(objMainWin, text="Please Log in", width=400)
    objPWDNote.config(bg="pink", fg="black")
    objPWDNote.grid(row=0, column=6)

    strLBCount = "There are {} entries".format(objItemsLB.size())
    objLBMsg = tk.Message(objMainWin, width=150, bg="white",
                          fg="black", text=strLBCount)
    objLBMsg.grid(column=1,row=9,sticky=tk.W)

    objCountdown = tk.Message(objMainWin, text="", width=200)
    objCountdown.config(bg="lightgreen", fg="black")
    if strPWD != "":
      objPWDText.delete(0, tk.END)
      objPWDText.insert(0, strPWD)
      Auth()

    if os.path.isfile(strICOFile):
      objMainWin.iconbitmap(strICOFile)
    else:
      binIco = b'AAABAAEAEBAQAAEABAAoAQAAFgAAACgAAAAQAAAAIAAAAAEABAAAAAAAgAAAAAAAAAAAAAAAEAAAAAAAAABeOREAAAAAAMTExAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEiIiIiIiIiESIiICIgIiIRIiIgIiAiIhEiIiAiICIiESIiICIgIiIRIiAgIiAiIhEiIgAAAAIiESIiIiIiICIREiIiIiIiIRERIRERERIREREhEREREhERESERERESERERIRERERIREREhEREREhERESERERESEREREiIiIiERGAAQAAgAEAAIABAACAAQAAgAEAAIABAACAAQAAgAEAAMADAADv9wAA7/cAAO/3AADv9wAA7/cAAO/3AADwDwAA'
      objFileOut = open(strICOFile, "wb")
      objFileOut.write(base64.b64decode(binIco))
      objFileOut.close()
      objMainWin.iconbitmap(strICOFile)
    objMainWin.mainloop()

  GUILayout()

def PrepConfig ():
  """
  Function that Creates a dictionary of configuration items
  for use by the configuration file creator
  Parameters:
    nothing
  Returns:
    dictionary object of all configuration items.
  """
  dictConfFile = {}
  dictConfFile["CLIPPYENABLE"] = FetchEnv("CLIPPYENABLE")
  dictConfFile["DB"] = FetchEnv("DB")
  dictConfFile["DBPWD"] = FetchEnv("DBPWD")
  dictConfFile["DBUSER"] = FetchEnv("DBUSER")
  dictConfFile["HIDEINPUT"] = FetchEnv("HIDEINPUT")
  dictConfFile["HOST"] = FetchEnv("HOST")
  dictConfFile["PORT"] = FetchEnv("PORT")
  dictConfFile["STORE"] = strStore
  dictConfFile["TABLE"] = FetchEnv("TABLE")
  dictConfFile["TOTPENABLE"] = FetchEnv("TOTPENABLE")
  dictConfFile["VALUECOLOR"] = FetchEnv("VALUECOLOR")
  dictConfFile["VAULT"] = strVault
  return dictConfFile

def CreateConfig(dictOut):
  """
  Function that Creates a configuration file that can be customized
  then used instead of environment variables
  Parameters:
    dictOut: Dictionary object of configuration items
  Returns:
    tru/false indicating success of failure
  """
  tmpResponse = GetFileHandle(strConf_File, "w")
  if isinstance(tmpResponse, str):
    print(tmpResponse)
    return False
  else:
    objFileOut = tmpResponse
    objFileOut.write("CLIPPYENABLE={}\n".format(dictOut["CLIPPYENABLE"]))
    objFileOut.write("DB={}\n".format(dictOut["DB"]))
    objFileOut.write("DBPWD={}\n".format(dictOut["DBPWD"]))
    objFileOut.write("DBUSER={}\n".format(dictOut["DBUSER"]))
    objFileOut.write("HIDEINPUT={}\n".format(dictOut["HIDEINPUT"]))
    objFileOut.write("HOST={}\n".format(dictOut["HOST"]))
    objFileOut.write("PORT={}\n".format(dictOut["PORT"]))
    objFileOut.write("STORE={}\n".format(dictOut["STORE"]))
    objFileOut.write("TABLE={}\n".format(dictOut["TABLE"]))
    objFileOut.write("TOTPENABLE={}\n".format(dictOut["TOTPENABLE"]))
    objFileOut.write("VALUECOLOR={}\n".format(dictOut["VALUECOLOR"]))
    objFileOut.write("VAULT={}\n".format(dictOut["VAULT"]))
    objFileOut.close()
    return True

def processConf(strConf_File):
  """
  Function that processes a configuration file that can be customized
  then used instead of environment variables
  Parameters:
    nothing
  Returns:
    Nothing
  """

  MsgOut("Looking for configuration file: {}".format(strConf_File))
  if os.path.isfile(strConf_File):
    MsgOut("Configuration File exists")
  else:
    MsgOut("Can't find configuration file {}, make sure it is the same directory "
             "as this script and named the same with ini extension".format(strConf_File))
    sys.exit(9)

  strLine = "  "
  dictConfig = {}
  MsgOut("Reading in configuration")
  objINIFile = open(strConf_File, "r")
  strLines = objINIFile.readlines()
  objINIFile.close()

  for strLine in strLines:
    strLine = strLine.strip()
    iCommentLoc = strLine.find("#")
    if iCommentLoc > -1:
      strLine = strLine[:iCommentLoc].strip()
    else:
      strLine = strLine.strip()
    if "=" in strLine:
      strConfParts = strLine.split("=")
      strVarName = strConfParts[0].strip()
      strValue = strConfParts[1].strip()
      dictConfig[strVarName] = strValue
      if strVarName == "include":
        MsgOut("Found include directive: {}".format(strValue))
        strValue = strValue.replace("\\", "/")
        if strValue[:1] == "/" or strValue[1:3] == ":/":
          MsgOut("include directive is absolute path, using as is")
        else:
          strValue = strBaseDir + strValue
          MsgOut("include directive is relative path,"
                   " appended base directory. {}".format(strValue))
        if os.path.isfile(strValue):
          MsgOut("file is valid")
          objINIFile = open(strValue, "r")
          strLines += objINIFile.readlines()
          objINIFile.close()
        else:
          MsgOut("invalid file in include directive")

  MsgOut("Done processing configuration, moving on")
  return dictConfig

def isInt(CheckValue):
  """
  Function checks if a value is an integer
  Parameters:
    CheckValue: String to be evaluated
  Returns:
    true/false
  """
  if isinstance(CheckValue, int):
    return True
  elif isinstance(CheckValue, str):
    if CheckValue.isnumeric():
      return True
    else:
      return False
  else:
    return False

def isFloat(fValue):
  """
  Function checks if a value is a floating point number
  Parameters:
    fValue: String to be evaluated
  Returns:
    true/false
  """
  if isinstance(fValue, (float, int, str)):
    try:
      fTemp = float(fValue)
    except ValueError:
      fTemp = "NULL"
  else:
    fTemp = "NULL"
  return fTemp != "NULL"

def DBClean(strText):
  """
  Function that removes undesirables from a string to prevent SQL injection
  Parameters:
    strText: String to be cleaned
  Returns:
    Clean string that is safe to send to database query
  """

  if strText.strip() == "":
    return "NULL"
  elif isInt(strText):
    return strText  # int(strText)
  elif isFloat(strText):
    return strText  # float(strText)
  else:
    strTemp = strText.encode("ascii", "ignore")
    strTemp = strTemp.decode("ascii", "ignore")
    strTemp = strTemp.replace("\\", "")
    strTemp = strTemp.replace("'", "")
    strTemp = strTemp.replace(";", "")
    return strTemp

def DBConnect(*, DBType, Server, DBUser="", DBPWD="", Database=""):
  """
  Function that handles establishing a connection to a specified database
  imports the right module depending on database type
  Parameters:
    DBType : The type of database server to connect to
                Supported server types are sqlite, mssql, mysql and postgres
    Server : Hostname for the database server
    DBUser : Database username
    DBPWD  : Password for the database user
    Database  : The name of the database to use
  Returns:
    Connection object to be used by query function, or an error string
  """
  strDBType = DBType
  strServer = Server
  strDBUser = DBUser
  strDBPWD = DBPWD
  strInitialDB = Database

  if strServer == "":
    return "Servername can't be empty"

  try:
    if strDBType == "sqlite":
      import sqlite3
      strVault = strServer
      strVault = strVault.replace("\\", "/")
      if strVault[-1:] == "/":
        strVault = strVault[:-1]
      if strVault[-3:] != ".db":
        strVault += ".db"
      lstPath = os.path.split(strVault)
      if not os.path.exists(lstPath[0]):
        os.makedirs(lstPath[0])
      return sqlite3.connect(strVault)
  except dboErr as err:
    return("SQLite Connection failure {}".format(err))

  try:
    if strDBType == "mssql":
      if not CheckDependency("pyodbc")["success"]:
        return "failed to install pyodbc. Please pip install pyodbc before using MS SQL option."
      import pyodbc as dbo
      if strDBUser == "":
        strConnect = (" DRIVER={{ODBC Driver 17 for SQL Server}};"
                      " SERVER={};"
                      " DATABASE={};"
                      " Trusted_Connection=yes;".format(strServer, strInitialDB))
      else:
        strConnect = (" DRIVER={{ODBC Driver 17 for SQL Server}};"
                      " SERVER={};"
                      " DATABASE={};"
                      " UID={};"
                      " PWD={};".format(strServer, strInitialDB, strDBUser, strDBPWD))
      return dbo.connect(strConnect)

    elif strDBType == "mysql":
      if not CheckDependency("pymysql")["success"]:
        return "failed to install pymysql. Please pip install pymysql before using mySQL option."
      import pymysql as dbo
      from pymysql import err as dboErr
      return dbo.connect(host=strServer, user=strDBUser, password=strDBPWD, db=strInitialDB)

    elif strDBType == "postgres":
      if not CheckDependency("psycopg2-binary")["success"]:
        return "failed to install psycopg2-binary. Please pip install psycopg2-binary before using PostgreSQL option."
      import psycopg2 as dbo
      return dbo.connect(host=strServer, user=strDBUser, password=strDBPWD, database=strInitialDB)
    else:
      return ("Unknown database type: {}".format(strDBType))
  except Exception as err:
    return ("Error: unable to connect: {}".format(err))

def DBQuery(*, SQL, dbConn):
  """
  Function that handles executing a SQL query using a predefined connection object
  imports the right module depending on database type
  Parameters:
    SQL    : The query to be executed
    dbConn : The connection object to use
  Returns:
    NoneType for queries other than select, DBCursor object with the results from the select query
    or error message as a string
  """
  strSQL = SQL
  try:
    dbCursor = dbConn.cursor()
    dbCursor.execute(strSQL)
    if strSQL[:6].lower() != "select":
      dbConn.commit()
      return None
    else:
      return dbCursor
  except Exception as err:
    return "Failed to execute query: {}\n{}\nLength of SQL statement {}\n".format(err, strSQL[:255], len(strSQL))

def StringEncryptor(strPWD, strData, encode=True):
  """
  This handles encrypting a string using AES.
  Adopted from https://stackoverflow.com/a/44212550/8549454
  Parameters:
    strPWD: Simple string with encryption password
    strData: Simple string with the data to be encrypted
    encode: Optional, defaults to true. A boolean to indicate the return should be Base64 encoded.
  Returns:
    Encrypted string, either raw or base64 encoded depending on the encode parameter
  """
  bKey = bytes(strPWD, "UTF-8")
  bData = bytes(strData, "UTF-8")  # use SHA-256 over our key to get a proper-sized AES key
  hKey = SHA256.new(bKey).digest()
  IV = Random.new().read(AES.block_size)  # generate IV
  objEncryptor = AES.new(hKey, AES.MODE_CBC, IV)  # calculate needed padding
  iPadLen = AES.block_size - len(bData) % AES.block_size
  bData += bytes([iPadLen]) * iPadLen  # store the IV at the beginning and encrypt
  oEncrypted = IV + objEncryptor.encrypt(bData)
  return base64.b64encode(oEncrypted).decode("UTF-8") if encode else oEncrypted

def StringDecryptor(strPWD, strData, decode=True):
  """
  This handles decrypting a string encrypted with AES
  Adopted from https://stackoverflow.com/a/44212550/8549454
  Parameters:
    strPWD: Simple string with encryption password
    strData: Simple string with the encrypted data
    encode: Optional, defaults to true. A boolean to indicate if the data is Base64 encoded.
  Returns:
    Decrypted clear text simple string
  """
  if decode:
      strData = base64.b64decode(strData.encode("UTF-8"))
  bKey = bytes(strPWD, "UTF-8")
  hKey = SHA256.new(bKey).digest()
  IV = strData[:AES.block_size]  # extract the IV from the beginning
  objEncryptor = AES.new(hKey, AES.MODE_CBC, IV)
  bClear = objEncryptor.decrypt(strData[AES.block_size:])  # decrypt
  iPadLen = bClear[-1]  # pick the padding value from the end;
  if bClear[-iPadLen:] != bytes([iPadLen]) * iPadLen:
      raise ValueError("Invalid padding...")
  bClear = bClear[:-iPadLen]  # remove the padding
  return bClear.decode("UTF-8")

def GetFileHandle(strFileName, strperm):
  """
  This wraps error handling around standard file open function
  Parameters:
    strFileName: Simple string with filename to be opened
    strperm: single character string, usually w or r to indicate read vs write. other options such as "a" are valid too.
  Returns:
    File Handle object
  """
  dictModes = {}
  dictModes["w"] = "writing"
  dictModes["r"] = "reading"
  dictModes["a"] = "appending"
  dictModes["x"] = "opening"

  cMode = strperm[0].lower()

  try:
    objFileOut = open(strFileName, strperm, encoding='utf8')
    return objFileOut
  except PermissionError:
    print("unable to open output file {} for {}, "
              "permission denied.".format(strFileName, dictModes[cMode]))
    return("Permission denied")
  except FileNotFoundError:
    print("unable to open output file {} for {}, "
              "Issue with the path".format(strFileName, dictModes[cMode]))
    return("key not found")

def DefineMenu():
  """
  Simple function that loads the menu into a global dictionary dictMenu
  Parameters:
    none
  Returns:
    Sets global variable dictMenu but returns nothing
  """
  global dictMenu

  dictMenu = {}
  dictMenu["help"]   = "Displays this message. Can also use /h -h and --help"
  dictMenu["quit"]   = "exit out of the script"
  dictMenu["add"]    = "Adds a new key value pair"
  dictMenu["del"]    = "removes the specified key"
  dictMenu["reset"]  = "Resets your stores so it is completely uninitialized"
  dictMenu["list"]   = "List out all keys"
  dictMenu["fetch"]  = "fetch a specified key"
  dictMenu["clip"]   = "put specified key value on the clipboard"
  dictMenu["passwd"] = "Change the password"
  dictMenu["totp"]   = "Displays TOTP code for the secret stored at the specified key"
  dictMenu["create"] = "Create a configuration file based on current environment"
  dictMenu["gui"]    = "Starts the GUI"
  dictMenu["login"]  = "Prompts for Vault password. Should never be needed manually as you are prompted when needed"

def DefineColors():
  """
  Simple function that loads the dictColor dictionary of colors
  Parameters:
    none
  Returns:
    Sets global variable dictColor but returns nothing
  """
  global dictColor
  dictColor = {}
  dictColor["black"] = "30"
  dictColor["red"] = "31"
  dictColor["green"] = "32"
  dictColor["orange"] = "33"
  dictColor["blue"] = "34"
  dictColor["purple"] = "35"
  dictColor["cyan"] = "36"
  dictColor["lightgrey"] = "37"
  dictColor["darkgrey"] = "90"
  dictColor["lightred"] = "91"
  dictColor["lightgreen"] = "92"
  dictColor["yellow"] = "93"
  dictColor["lightblue"] = "94"
  dictColor["pink"] = "95"
  dictColor["lightcyan"] = "96"

def SQLOp(strCmd, strKey="", strValue=""):
  """
  This handles all database operations
  Parameters:
    strCmd: Which operation is needed
    strkey: Optional, defaults to an empty string. The name of the key part of the key value pair
    strValue: Optional, defaults to an empty string. The value part of the key value pair.
  Returns:
    Decrypted clear text simple string
  """
  if strCmd == "Create":
    strTableCreate = "CREATE TABLE "
    if strStore != "mssql":
      strTableCreate += "IF NOT EXISTS "
      strTextField = "text not null"
    else:
      strTextField = "varchar(MAX) not null"
    strTableCreate += strTable + "(strKey " + strTextField + ", strValue " + strTextField + ");"
    if strStore == "mssql":
      strSQL = "select OBJECT_ID('{}', 'U')".format(strTable)
      dbCursor = DBQuery(SQL=strSQL, dbConn=dbConn)
      strReturn = dbCursor.fetchone()
      if strReturn[0] is None:
        dbCursor = DBQuery(SQL=strTableCreate, dbConn=dbConn)
        MsgOut("Query complete.")
        if isinstance(dbCursor, str):
          print("Failed to create table on MS SQL. Results is only the following string: {}".format(dbCursor))
          return False
      else:
        MsgOut("Table already exists")
        return True
    else:
      dbCursor = DBQuery(SQL=strTableCreate, dbConn=dbConn)
      if isinstance(dbCursor, str):
        print("Failed to create table on {}. Results is only the following string: {}".format(strStore, dbCursor))
        return False
      else:
        return True

  elif strCmd == "select":
    strSQL = "select strKey, strValue from " + strTable
    if strKey != "":
      strSQL += " where strKey = '{}';".format(strKey)
    dbCursor = DBQuery(SQL=strSQL, dbConn=dbConn)
    if isinstance(dbCursor, str):
      print("Failed to fetch data on {}. Results is only the following string: {}".format(
          strStore, dbCursor))
      return False
    else:
      return dbCursor.fetchall()

  elif strCmd == "update":
    strSQL = "update {} set strValue = '{}' where strKey = '{}';".format(strTable, strValue, strKey)
    dbCursor = DBQuery(SQL=strSQL, dbConn=dbConn)
    if isinstance(dbCursor, str):
      print("Failed to update data on {}. Results is only the following string: {}".format(
          strStore, dbCursor))
      return False
    else:
      return True

  elif strCmd == "insert":
    strSQL = "insert into {} (strKey,strValue) values('{}','{}');".format(strTable, strKey, strValue)
    dbCursor = DBQuery(SQL=strSQL, dbConn=dbConn)
    if isinstance(dbCursor, str):
      print("Failed to update data on {}. Results is only the following string: {}".format(
          strStore, dbCursor))
      return False
    else:
      return True

  elif strCmd == "delete":
    strSQL = "delete from " + strTable
    if strKey != "":
      strSQL += " where strKey = '{}';".format(strKey)
    dbCursor = DBQuery(SQL=strSQL, dbConn=dbConn)
    if isinstance(dbCursor, str):
      print("Failed to update data on {}. Results is only the following string: {}".format(
          strStore, dbCursor))
      return False
    else:
      return True

  else:
    print("Unsupported SQL operation: {}".format(strCmd))

def UserLogin():
  """
  Simple function that handles validating that password is valid across all items in the vault
  Parameters:
    none
  Returns:
    true/false boolean to indicate if password supplied is good or not
  """
  global strPWD
  global bLoggedIn

  if strPWD == "":
    strPWD = maskpass.askpass(prompt="Please provide vault password: ", mask="*")
  bStatus = CheckVault()
  if bStatus is None:
    if len(lstVault) > 0:
      if FetchItem(lstVault[0]) == "Failed to decrypt":
        print("unable to decrypt vault, please try to login again")
        bLoggedIn = False
        strPWD = ""
        return False
    AddItem(strCheckKey, strCheckValue)
    MsgOut("Vault Initialized")
    bLoggedIn = True
    return True
  elif bStatus:
    MsgOut("Password is good")
    bLoggedIn = True
    return True
  else:
    print("unable to decrypt vault, please try again")
    bLoggedIn = False
    strPWD = ""
    return False

def Fetch2Clip(strKey):
  """
  Function that fetches the specified key from the datastore and decrypts it.
  Decrypted value is then placed on the clipboard and not shown.
  Parameters:
    strKey: The name of the key to be fetched
  Returns:
    nothing
  """
  strValue = FetchItem(strKey)
  if strValue != False:
    try:
      pyperclip.copy(strValue)
      print("Value for {} put on the clipboard".format(strKey))
    except pyperclip.PyperclipException:
      print("Failed to find the clipboard, so outputting it here")

def ShowTOTP(strKey):
  """
  Function that fetches the specified key from the datastore and decrypts it.
  Decrypted value is then used to generate a time based one time token.
  Parameters:
    strKey: The name of the key to be fetched
  Returns:
    A string with the generated token, or bolean false on failure
  """
  strB32Pattern = "[^A-Z2-7]"
  strValue = FetchItem(strKey)
  if strValue != False:
    if strValue[:15] == "otpauth://totp/":
      objTOPT = pyotp.parse_uri(strValue)
      return objTOPT.now()
    elif len(re.findall(strB32Pattern, strValue)) == 0:
      objTOPT = pyotp.TOTP(strValue)
      return objTOPT.now()
    else:
      print("Not a valid TOTP Secret")
      return False
  else:
    return False

def ListItems():
  """
  Function that just lists out all the keys in the store.
  Parameters:
    none
  Returns:
    nothing
  """
  if len(lstVault) > 0:
    MsgOut("\nHere are all the keys in the vault:")
    for strItem in lstVault:
      if isinstance(strItem,bytes):
        strItem = strItem.decode("UTF-8")
      if strItem != strCheckKey:
        print("{}".format(strItem))

def CheckVault():
  """
  Function used by login function to check the vault.
  Parameters:
    none
  Returns:
    true/false indicating if the vault is good or not
  """
  if strCheckKey in lstVault:
    strInitstr = FetchItem(strCheckKey)
    if strInitstr == strCheckValue:
      return True
    else:
      return False
  else:
    return None

def DisplayHelp():
  """
  Function that displays a help message.
  Parameters:
    none
  Returns:
    none
  """
  lstDontShow = ["list", "fetch", "clip", "del", "passwd","totp"]
  print("\nHere are the commands you can use:")
  for strItem in dictMenu:
    if len(lstVault) > 1:
      if strItem != "clip" or bClippy:
        print("{} : {}".format(strItem, dictMenu[strItem]))
      #if strItem != "totp" or bTOTP:
      #  print("{} : {}".format(strItem, dictMenu[strItem]))
    elif strItem not in lstDontShow:
      print("{} : {}".format(strItem, dictMenu[strItem]))

def ChangePWD(strNewPWD):
  """
  Function that loops through all items in the store, decrypts it then re-encrypts with new password.
  Parameters:
    none
  Returns:
    nothing
  """
  global lstFailed
  global strPWD
  bSuccess = True
  lstFailed = []
  for strKey in lstVault:
    strValue = FetchItem(strKey)
    if strValue:
      if AddItem(strKey, strValue,False,strNewPWD):
        MsgOut("key {} successfully changed".format(strKey))
      else:
        MsgOut("Failed to change key {}".format(strKey))
        bSuccess = False
        lstFailed.append(strKey)
    else:
      MsgOut("Failed to change key {}".format(strKey))
      bSuccess = False
      lstFailed.append(strKey)

  strPWD = strNewPWD
  return bSuccess

def ProcessCMD(objCmd):
  """
  Function that process all the user commands, whether in the shell or from command arguments.
  Parameters:
    objCmd: The command string, either simple string or an array of strings
  Returns:
    nothing
  """
  global bCont
  global bQuiet

  strCmd = ""
  lstCmd = []
  if isinstance(objCmd,str):
    lstCmd = objCmd.split()
  elif isinstance(objCmd,list):
    lstCmd = objCmd
  else:
    print("Can't deal with command of type {}".format(type(objCmd)))
    return
  if len(lstCmd) > 0:
    strCmd = lstCmd[0]
  else:
    print("Got an empty list, don't know what to do with that")
    return

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

  elif strCmd == "add":
    bLogin = True
    if not bLoggedIn:
      bLogin = UserLogin()
    if bLogin:
      if len(lstCmd) > 1:
        strKeyName = lstCmd[1]
      else:
        strKeyName = input("Please specify keyname: ")
      if len(lstCmd) > 2:
        strKeyValue = " ".join(lstCmd[2:])
      else:
        if bHideValueIn:
          strKeyValue = maskpass.askpass(
              prompt="Please specify the value for key {}: ".format(strKeyName), mask="*")
        else:
          strKeyValue = input("Please specify the value for key {}: ".format(strKeyName))
      if AddItem(strKeyName,strKeyValue):
        print("key {} successfully created".format(strKeyName))
        ListCount()
      else:
        print("Failed to create key {}".format(strKeyName))
  elif strCmd == "list":
    ListItems()
  elif strCmd == "passwd":
    bLogin = True
    if not bLoggedIn:
      bLogin = UserLogin()
    if bLogin:
      strNewPWD = maskpass.askpass(
          prompt="Please provide New password: ", mask="*")
      if(ChangePWD(strNewPWD)):
        print("Password successfully changed")
      else:
        print("Password changed failed on {} of {} entries. "
        "The following keys failed {}".format(len(lstFailed),len(lstVault),(lstFailed)))
  elif strCmd == "fetch":
    bLogin = True
    if not bLoggedIn:
      bLogin = UserLogin()
    if bLogin:
      if len(lstCmd) > 1:
        strKey = lstCmd[1]
      else:
        ListItems()
        strKey = input("Please provide name of key you wish to fetch: ")
      strValue = FetchItem(strKey)
      if strValue != False:
        if bQuiet:
          print("{}{}{}".format(strFormat, strValue, strFormatReset))
        else:
          print("\nThe value of '{}' is:{}{}{}\n".format(
            strKey, strFormat, strValue, strFormatReset))
  elif strCmd == "del":
    if len(lstCmd) > 1:
      strKey = lstCmd[1]
    else:
      ListItems()
      strRed = "\x1b[1;{}m".format(31)
      print("{}PLEASE NOTE THIS ACTION IS IRREVERSABLE AND CARRIES NO CONFIRMATION{}".format(
          strRed, strFormatReset))
      strKey = input("Please provide name of key you wish to remove: ")
    if DelItem(strKey):
      print("Successfully deleted key {}".format(strKey))
      ListCount()
    else:
      print("Failed to deleted key {}".format(strKey))
  elif strCmd == "reset":
    ListItems()
    strRed = "\x1b[1;{}m".format(31)
    print("{}PLEASE NOTE THIS ACTION IS IRREVERSABLE AND COMPLETELY NUKES YOUR STORE{}".format(
        strRed, strFormatReset))
    strKey = input("Please type yes to confirm, all other input will considered as no: ")
    if strKey.lower() == "yes":
      if ResetStore():
        print("Successfully reset the store")
      else:
        print("Failed to reset the store")
  elif strCmd == "create":
    if(CreateConfig(PrepConfig())):
      print("Successfully created configuration file {}. Please check it out and modify as needed.".format(strConf_File))
    else:
      print("Failed to create a configuration file")
  elif strCmd[:4] == "clip":
    if not bClippy:
      print("Clip is not supported on your system")
      return
    bLogin = True
    if not bLoggedIn:
      bLogin = UserLogin()
    if bLogin:
      if len(lstCmd) > 1:
        strKey = lstCmd[1]
      else:
        ListItems()
        strKey = input("Please provide name of key you wish to fetch: ")
      Fetch2Clip(strKey)
  elif strCmd == "totp":
    if not bTOTP:
      print("TOTP Function is disabled")
      return
    bLogin = True
    if not bLoggedIn:
      bLogin = UserLogin()
    if bLogin:
      if len(lstCmd) > 1:
        strKey = lstCmd[1]
      else:
        ListItems()
        strKey = input("Please provide name of key you wish to get TOTP code for: ")
      strResponse = ShowTOTP(strKey)
      if isinstance(strResponse,str):
        if bQuiet:
          print("{}{}{}".format(strFormat, strResponse, strFormatReset))
        else:
          print("Your code is: {} {} {}".format(strFormat, strResponse, strFormatReset))
        if bClippy:
          pyperclip.copy(strResponse)
          MsgOut("Your code is on the clipboard as well")
      else:
        print("failed to generate code")
  elif strCmd == "login":
    UserLogin()
  elif strCmd == "gui":
    bQuiet = True
    ShowGUI()
  else:
    print("Not implemented")

def FetchEnv(strVarName):
  """
  Function that fetches the specified content of specified environment variable,
  converting nonetype to empty string.
  Parameters:
    strVarName: The name of the environment variable to be fetched
  Returns:
    The content of the environment or empty string
  """

  if os.getenv(strVarName) != "" and os.getenv(strVarName) is not None:
    return os.getenv(strVarName)
  else:
    if strVarName in dictConfig:
      return dictConfig[strVarName]
    else:
      return ""

def VaultInit():
  """
  Function that handles initial inititialization of the specified store.
  Parameters:
    none
  Returns:
    nothing returned. Applicable global variables are set.
  """
  global objRedis
  global strVault
  global dbConn
  lstSQLDB = lstDBTypes.copy()
  lstSQLDB.remove("sqlite")

  if strStore.lower() == "files":
    MsgOut("Using filsystem store")
    if strVault == "":
      MsgOut("No command argument vault specifier, checking environment variable")
      strVault = FetchEnv("VAULT")
    if strVault != "":
      MsgOut("Found {} in env for vault path".format(strVault))
    else:
      MsgOut("no vault environment valuable")
    if strVault == "":
      strVault = strBaseDir + strDefVault + "/"
      MsgOut("No vault path provided in either env or argument. Defaulting vault path to: {}".format(strVault))
    else:
      MsgOut("Using vault path of {}".format(strVault))
    strVault = strVault.replace("\\", "/")
    if strVault[-1:] != "/":
      strVault += "/"
    if not os.path.exists(strVault):
      os.makedirs(strVault)
      MsgOut(
          "\nPath '{0}' for vault didn't exists, so I create it!\n".format(strVault))

  elif strStore.lower() == "redis":
    MsgOut("Using redis store")
    if not CheckDependency("redis")["success"]:
      print("failed to install redis. Please pip install redis prior to using redis store.")
    import redis
    strRedisHost = FetchEnv("HOST")
    iRedisPort = FetchEnv("PORT")
    iRedisDB = FetchEnv("DB")
    strDBpwd = FetchEnv("DBPWD")
    lstHost = strRedisHost.split(".")
    MsgOut("Connecting to redis server at ...{}".format(".".join(lstHost[-3:])))
    if strDBpwd != "":
      MsgOut("with password that starts with {}".format(strDBpwd[:2]))
    objRedis = redis.Redis(
        host=strRedisHost, port=iRedisPort, db=iRedisDB, password=strDBpwd)

  elif strStore.lower() in lstSQLDB:
    strServer = FetchEnv("HOST")
    strInitialDB = FetchEnv("DB")
    strDBUser = FetchEnv("DBUSER")
    strDBpwd = FetchEnv("DBPWD")
    dbConn = DBConnect(DBType=strStore, Server=strServer,
                       DBUser=strDBUser, DBPWD=strDBpwd, Database=strInitialDB)
    if isinstance(dbConn, str):
      print("Failed to connect to {} at {}. Error: {}".format(
          strStore, strVault, dbConn))
      sys.exit(9)
    else:
      MsgOut("Connection to {} at {} successful.".format(strStore, strServer))
    if not SQLOp("Create"):
      print("Failed to create table")
      sys.exit(9)

  elif strStore.lower() == "sqlite":
    if strVault == "":
      MsgOut("No command argument vault specifier, checking environment variable")
      strVault = FetchEnv("VAULT")
    if strVault != "":
      MsgOut("Found {} in env for vault path".format(strVault))
    else:
      MsgOut("no vault environment valuable")
    if strVault == "":
      strVault = strBaseDir + strDefVault + ".db"
      MsgOut("No vault path provided in either env or argument. Defaulting vault path to: {}".format(strVault))
    else:
      MsgOut("Using vault path of {}".format(strVault))
    dbConn = DBConnect(DBType=strStore, Server=strVault)
    if isinstance(dbConn,str):
      print("Failed to connect to {} at {}. Error: {}".format(strStore,strVault,dbConn))
      sys.exit(9)
    else:
      MsgOut("Connection to {} at {} successful.".format(strStore, strVault))
    if SQLOp("Create"):
      MsgOut("Table created")
    else:
      print("Failed to create table")
      sys.exit(9)

  else:
    print("Unsupported store {}".format(strStore))
    sys.exit(9)

def ListCount():
  """
  Function that displays information about status of the vault and number of members.
  Parameters:
    none
  Returns:
    nothing
  """

  global lstVault

  if strStore.lower() == "files":
    lstVault = os.listdir(strVault)
  elif strStore.lower() == "redis":
    try:
      lstTmp = objRedis.keys("*")
    except Exception as err:
      print("Failed to fetch keys from Redis: {}".format(err))
      sys.exit(9)
    lstVault = []
    for strItem in lstTmp:
      if isinstance(strItem, bytes):
        lstVault.append(strItem.decode("UTF-8"))
      else:
        lstVault.append(strItem)
  elif strStore.lower() in lstDBTypes:
    lstResult = SQLOp("select")
    lstVault = []
    if isinstance(lstResult,(list,tuple)):
      for Temp in lstResult:
        lstVault.append(Temp[0])
    else:
      print("Failed to list out the vault. Result is type {} with value of {}".format(type(lstResult),lstResult))
      sys.exit(9)
  else:
    print("Unknown store type {} in ListCount".format(strStore))

  if strCheckKey in lstVault:
    iVaultLen = len(lstVault) - 1
  else:
    iVaultLen = len(lstVault)
  if iVaultLen > 0:
    MsgOut("Vault is initialized and contains {} entries".format(iVaultLen))
  else:
    if strCheckKey in lstVault:
      print("Vault is inilized with no entries")
    else:
      print("Vault is uninilized, need to add an item to initialize")

def AddFileItem(strKey, strValue, bConf=True, strPass=""):
  """
  Function that encrypts the string provided and
  stores the key value pair in the file system data store
  Parameters:
    strKey: The name of the key part of the key value pair
    strValue: The value part of the key value pair
    bConf: Optional, defaults to True. If key updates should be confirmed
    strPass: Optional, defaults to blank string. Use a password other than
              that validated by login function
  Returns:
    True/false boolean to indicate if the was successful or not
  """
  if strPass == "":
    strPass = strPWD
  strFileOut = strVault + strKey
  if os.path.exists(strFileOut) and bConf:
    print("Key '{}' already exists, do you wish to overwrite it?".format(strKey))
    strResp = input("Please type yes to confirm, all other input is a no: ")
    if strResp.lower() != "yes":
      return False

  tmpResponse = GetFileHandle(strFileOut, "w")
  if isinstance(tmpResponse, str):
    print(tmpResponse)
    return False
  else:
    objFileOut = tmpResponse
    objFileOut.write(StringEncryptor(strPass, strValue))
    objFileOut.close()
    return True

def AddRedisItem(strKey, strValue, bConf=True, strPass=""):
  """
  Function that encrypts the string provided and
  stores the key value pair in the Redis data store
  Parameters:
    strKey: The name of the key part of the key value pair
    strValue: The value part of the key value pair
    bConf: Optional, defaults to True. If key updates should be confirmed
    strPass: Optional, defaults to blank string. Use a password other than
              that validated by login function
  Returns:
    True/false boolean to indicate if the value was successful or not
  """
  if strPass == "":
    strPass = strPWD
  if strKey in lstVault and bConf:
    print("Key '{}' already exists, do you wish to overwrite it?".format(strKey))
    strResp = input("Please type yes to confirm, all other input is a no: ")
    if strResp.lower() != "yes":
      return False
  if objRedis.set(strKey, StringEncryptor(strPass, strValue)):
    return True
  else:
    return False

def AddSQLItem(strKey, strValue, bConf=True, strPass=""):
  """
  Function that encrypts the string provided and
  stores the key value pair in the selected database
  Parameters:
    strKey: The name of the key part of the key value pair
    strValue: The value part of the key value pair
    bConf: Optional, defaults to True. If key updates should be confirmed
    strPass: Optional, defaults to blank string. Use a password other than
              that validated by login function
  Returns:
    True/false boolean to indicate if the value was successful or not
  """
  if strPass == "":
    strPass = strPWD
  if strKey in lstVault:
    if bConf:
      print("Key '{}' already exists, do you wish to overwrite it?".format(strKey))
      strResp = input("Please type yes to confirm, all other input is a no: ")
    else:
      strResp = "yes"
    if strResp.lower() == "yes":
      return SQLOp("update", strKey, StringEncryptor(strPass, strValue))
    else:
      return False
  else:
    return SQLOp("insert", strKey, StringEncryptor(strPass, strValue))

def AddItem(strKey, strValue, bConf=True, strPass=""):
  """
  Function that calls the right function to encrypt and store the value depend on selected store
  Parameters:
    strKey: The name of the key part of the key value pair
    strValue: The value part of the key value pair
    bConf: Optional, defaults to True. If key updates should be confirmed
    strPass: Optional, defaults to blank string. Use a password other than
              that validated by login function
  Returns:
    True/false boolean to indicate if the was successful or not
  """
  strKey = DBClean(strKey)
  if strStore.lower() == "files":
    return AddFileItem(strKey, strValue, bConf, strPass)
  elif strStore.lower() == "redis":
    return AddRedisItem(strKey, strValue, bConf, strPass)
  elif strStore.lower() in lstDBTypes:
    return AddSQLItem(strKey, strValue, bConf, strPass)
  else:
    print("Unknown store {}".format(strStore))
    return None

def FetchFileItem(strKey):
  """
  Function that fetches the specified key from the file store and decrypts it.
  Parameters:
    strKey: The name of the key to be fetched
  Returns:
    Either the decrypted string or boolean false to indicate a failure
  """
  strFileIn = strVault + strKey
  tmpResponse = GetFileHandle(strFileIn, "r")
  if isinstance(tmpResponse, str):
    print(tmpResponse)
    return False
  else:
    objFileIn = tmpResponse
    strValue = objFileIn.read()
    objFileIn.close()
    try:
      return StringDecryptor(strPWD, strValue)
    except ValueError:
      MsgOut("Failed to decrypt the vault")
      return False

def FetchRedisItem(strKey):
  """
  Function that fetches the specified key from Redis and decrypts it.
  Parameters:
    strKey: The name of the key to be fetched
  Returns:
    Either the decrypted string or boolean false to indicate a failure
  """
  strValue = objRedis.get(strKey)
  strValue = strValue.decode("utf-8")
  try:
    return StringDecryptor(strPWD, strValue)
  except ValueError:
    MsgOut("Failed to decrypt the vault")
    return False

def FetchSQLItem(strKey):
  """
  Function that fetches the specified key from database and decrypts it.
  Parameters:
    strKey: The name of the key to be fetched
  Returns:
    Either the decrypted string or boolean false to indicate a failure
  """
  lstResult = SQLOp("select",strKey)
  strValue = lstResult[0][1]
  try:
    return StringDecryptor(strPWD, strValue)
  except ValueError:
    MsgOut("Failed to decrypt the vault")
    return False

def FetchItem(strKey):
  """
  Function that calls the right function to fetch and decrypt depend on selected store
  Parameters:
    strKey: The name of the key to be fetched
  Returns:
    Either the decrypted string or boolean false to indicate a failure
  """
  strKey = DBClean(strKey)
  if strKey not in lstVault:
    return "  -- ERROR: Invalid key {}. Use list option for a list of valid keys".format(strKey)
  if strStore.lower() == "files":
    return FetchFileItem(strKey)
  elif strStore.lower() == "redis":
    return FetchRedisItem(strKey)
  elif strStore.lower() in lstDBTypes:
    return FetchSQLItem(strKey)
  else:
    return "Unknown store {}".format(strStore)

def DelItem(strKey):
  """
  Function that removes a key from the datastore
  Parameters:
    strKey: The name of the key part of the key value pair
  Returns:
    Nothing
  """
  strKey = DBClean(strKey)
  if strStore.lower() == "files":
    if strKey != "":
      strFileName = strVault + strKey
      try:
        os.remove(strFileName)
        return True
      except PermissionError:
        print("unable to delete file {}, "
              "permission denied.".format(strFileName))
        return False
      except FileNotFoundError:
        print("unable to delete file {}, "
              "Issue with the path".format(strFileName))
        return False
  elif strStore.lower() == "redis":
    objRedis.delete(strKey)
    return True
  elif strStore.lower() in lstDBTypes:
    return SQLOp("delete",strKey)
  else:
    print("Unknown store {}".format(strStore))
    return False

def ResetStore():
  """
  Function that completely resets the choosen store to a blank slate
  Parameters:
    none
  Returns:
    Nothing
  """
  if strStore.lower() == "files":
    try:
      shutil.rmtree(strVault)
    except PermissionError:
      print("unable to delete file {}, "
            "permission denied.".format(strVault))
    except FileNotFoundError:
      print("unable to delete file {}, "
            "Issue with the path".format(strVault))
    except OSError as err:
      print("unable to delete {}, "
            "OS Error {}".format(strVault, err))

  elif strStore.lower() == "redis":
    objRedis.flushdb()
  elif strStore.lower() in lstDBTypes:
    return SQLOp("delete")
  else:
    print("Unknown store {}".format(strStore))
    return None

def MsgOut(strMsg):
  """
  Function that check quiet environment variable and only prints if it is false
  Parameters:
    strMsg: String to be printed
  Returns:
    Nothing
  """

  if not bQuiet:
    print(strMsg)

def main():
  """
  Initial entry point where some of the initialization takes place.
  Parameters:
    none
  Returns:
    nothing
  """
  global bCont
  global strVault
  global strPWD
  global bClippy
  global bTOTP
  global bHideValueIn
  global strFormat
  global strFormatReset
  global pyperclip
  global pyotp
  global strStore
  global strBaseDir
  global strTable
  global bQuiet
  global dictConfig
  global strConf_File
  global iShowTime
  global bAutoHide
  global strVersion

  DefineMenu()
  DefineColors()

  dictConfig = {}

  strQuiet = FetchEnv("QUIET")
  if strQuiet.lower() == "true":
    bQuiet = True
  else:
    bQuiet = False

  lstSysArg = sys.argv
  iLoc = lstSysArg[0].rfind(".")
  strConf_File = lstSysArg[0][:iLoc] + ".ini"

  if os.path.isfile(strConf_File):
    dictConfig = processConf(strConf_File)
    MsgOut("Configuration file has been processed")


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

  MsgOut("This is a simple secrets vault script. Enter in a key value pair "
        "and the value will be encrypted with AES-256 using MODE_CBC and stored under the key.")
  MsgOut("This is running under Python Version {}".format(strVersion))
  MsgOut("Running from: {}".format(strRealPath))
  dtNow = time.asctime()
  MsgOut("The time now is {}".format(dtNow))

  strEnableClippy = FetchEnv("CLIPPYENABLE")
  if strEnableClippy.lower() == "false":
    bClippy = False
  else:
    if not CheckDependency("pyperclip")["success"]:
      print("failed to install pyperclip. Please pip install pyperclip or disable clipboard support.")

    import pyperclip
    try:
      pyperclip.paste()
      MsgOut("Clipboard seems good so turning that on")
      bClippy = True
    except pyperclip.PyperclipException:
      MsgOut("Failed to find the clipboard, so turning clippy off")
      bClippy = False

  bTOTP = True
  strEnableTOTP = FetchEnv("TOTPENABLE")
  if strEnableTOTP.lower() == "false":
    bTOTP = False
    MsgOut("Per environment variable, TOTP function has been turned off")
  else:
    if not CheckDependency("pyotp")["success"]:
      print("failed to install pyotp. Please pip install pyotp or disable TOTP support.")

    import pyotp

  iShowTime = FetchEnv("SHOWTIME")
  strAutoHide = FetchEnv("AUTOHIDE")
  strStore = FetchEnv("STORE")
  strPWD = FetchEnv("VAULTPWD")
  strHideIn = FetchEnv("HIDEINPUT")
  strValueColor = FetchEnv("VALUECOLOR")
  strTable = FetchEnv("TABLE")

  if isInt(iShowTime):
    iShowTime = int(iShowTime)
  else:
    iShowTime = iDefShowTime
  if strStore == "":
    MsgOut("No store type environment, defaulting to {} store".format(strDefStore))
    strStore = strDefStore

  if strTable == "":
    MsgOut("No Table name in environment, defaulting to {}".format(strDefTable))
    strTable = strDefTable

  if strAutoHide == "":
    bAutoHide = bDefAutoHide
  elif strAutoHide.lower() == "true":
    bAutoHide = True
  else:
    bAutoHide = False

  if strHideIn == "":
    bHideValueIn = bDefHide
  elif strHideIn.lower() == "true":
    bHideValueIn = True
  else:
    bHideValueIn = False
  if strValueColor == "":
    iColorID = dictColor[strDefValueColor]
  else:
    iColorID = dictColor[strValueColor]
  strFormat = "\x1b[1;{}m".format(iColorID)
  strFormatReset = "\x1b[0;0m"

  strVault = ""
  if len(lstSysArg) > 1:
    if lstSysArg[1][:5].lower() == "vault":
      strVault = lstSysArg[1][6:]
      MsgOut("Found vault in argument: {}".format(strVault))
      del lstSysArg[1]

  VaultInit()
  if len(lstSysArg) > 1:
    ListCount()
    bCont = False
    del lstSysArg[0]
    ProcessCMD(lstSysArg)
  else:
    if bQuiet:
      bCont = False
      ListCount()
      DisplayHelp()
    else:
      bCont = True

  while bCont:
    ListCount()
    DisplayHelp()
    strCmd = input("Please enter a command: ")
    ProcessCMD(strCmd)




if __name__ == '__main__':
    main()
