# Environmental Variables per store type

## Filesystem

All variables are optional. Vault default is the working directory. If PWD is absent, you will be prompted for it. All other defaults are as shown

```
CLIPPYENABLE: 'true' 
HIDEINPUT: 'true' 
PWD: SuperStrongsecretPWD!
STORE: files
VALUECOLOR: blue
VAULT: ~/PieVault 
```

## SQLite

Only required variable is store. Vault default is the working directory. If PWD is absent, you will be prompted for it. All other defaults are as shown

```
CLIPPYENABLE: 'true'
HIDEINPUT: 'true'
PWD: SuperStrongsecretPWD!
STORE: sqlite
VALUECOLOR: blue
VAULT: ~/PieVault 
```

## Redis

```
CLIPPYENABLE: 'true' # optional defaults to true
HIDEINPUT: 'true' # optional defaults to true
PWD: SuperStrongsecretPWD!
STORE: redis #required
VALUECOLOR: blue # Optional defaults to red
DB: '0' #required
HIDEINPUT: 'true' # Optional, defaults to false
HOST: localhost # required
PORT: '6379' # required
DBPWD: SecretDBPassword   # Required if configured on your Redis instance, otherwise it must be left blank or not configured
```

