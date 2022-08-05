# PiVault
This is a very simply CLI based secrets manager written in python. This has been tested to my knowledge on 3.6, 3.7 and 3.10, and on Windows 10, Windows 11, ubuntu 18, ubuntu 20, OpenBSD and MacOS. More testing is appreciated and if you find issues or have a feature request please log it under the issue tab.

When I say simple you can store key/value pair, fetch a value based on a key and display it, and fetch a value based on a key and place it on the clipboard. That's pretty much it, that's how simple it is. The clipboard feature works across SSH if you have X11 setup properly on both the client and the server. If you have xclip installed and can do all sorts of X11 stuff, then the clipboard should work across the SSH connection. Otherwise the clipboard feature is unavailable. You'll get a message when you start the script whether clipboard feature is working or not. 

Everything is a key value pair where the key is public but the value is secret. The value is encrypted using AES-256 in MODE_CBC, if you don't know what that means, just know that is one of the best encryption methods available when this was written in August of 2022. When used with a strong, un-guessable, password it has not been cracked as of this writing.  After the value is encrypted it is base64 encoded and stored under the key in the chosen storage engine. To begin with only file system is available as a storage engine, however I've got plan to add database and Redis support. I also plan to offer PGP encryption as well. This ReadMe will be updated as I complete these options. 

For the filesystem storage engine each key value pair is stored in its own file in a specified folder, where the key is the filename and the content of the file is the encrypted base64 encoded blob. If no folder path is provided then a folder called `VaultData` is created in the same directory as the script. You can provide an alternative path in one of two ways:

- Create and environment variable called VAULT with the preferred vault path, relative to the script or absolute path
- Supply the path as a command argument during execution. The argument should be formatted as `vault=~/MyVault` and it needs to be the first argument

By default password entries are masked but value entries are not. If you wish to have value entries masked, create a environment variable called HIDEINPUT and set it to true.

Speaking of passwords and environment variables, you can define an environment variable called PWD and assign your vault password to it. Don't do this lightly though, think through your threat matrix and evaluate if this fits into your risk model. Depending on your situation this cold be a risky thing to do. For most people it is fine to do this and makes it easy to use a long and complex password which increases your security.

When you fetch a stored value, the decrypted string is printed in red font by default. You can change this by defining an environment variable called VALUECOLOR and setting it to one these colors: black, red, green, orange, blue, purple, cyan, lightgrey, darkgrey, lightred, lightgreen, yellow, lightblue, pink, lightcyan.

If you initiate the script without any arguments, except maybe the vault argument, you will be dropped into an interactive shell. You can also accomplish everything by using just command arguments. 

```
Here are the commands you can use:
help : Displays this message. Can also use /h -h and --help
quit : exit out of the interactive shell. Exit works as well
add : Adds a new key value pair
list : List out all keys
fetch : fetch a specified key
clippy : put specified key value on the clipboard
passwd : Change the password of the vault
```

Here are some examples:

```
python3 PiVault.py add testkey15 This is the value 15
```

This creates a new entry called testkey15 and encrypts the string "This is the value #15" and stores it in it. 

```
python3 PiVault.py fetch testkey15
```

This decrypts entry testkey15 and displays the decrypted string in the console

```
python3 PiVault.py clippy testkey15
```

This decrypts entry testkey15 and places the decrypted string on the clipboard

```
python3 PiVault.py vault=MyVault add testkey17 this is a key value for new vault
```

This creates a new entry called testkey17 and encrypts the string "this is a key value for new vault" and stores it in a vault called `MyVault` in the current directory
