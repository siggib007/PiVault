# Environmental Variables per store type

## Filesystem

All variables are optional. Vault default is the working directory. If PWD is absent, you will be prompted for it. All other defaults are as shown

```
CLIPPYENABLE: 'true' 
HIDEINPUT: 'true' 
VAULTPWD: SuperStrongsecretPWD!
STORE: files
VALUECOLOR: blue
VAULT: ~/PieVault 
```

## SQLite

Only required variable is store. Vault default is the working directory. If PWD is absent, you will be prompted for it. All other defaults are as shown

```
CLIPPYENABLE: 'true'
HIDEINPUT: 'true'
VAULTPWD: SuperStrongsecretPWD!
STORE: sqlite
VALUECOLOR: blue
VAULT: ~/PieVault 
```

## Redis

```
CLIPPYENABLE: 'true' # optional defaults to true
HIDEINPUT: 'true' # optional defaults to true
VAULTPWD: SuperStrongsecretPWD!
STORE: redis #required
VALUECOLOR: blue # Optional defaults to red
DB: '0' #required
HIDEINPUT: 'true' # Optional, defaults to false
HOST: localhost # required
PORT: '6379' # required
DBPWD: SecretDBPassword   # Required if configured on your Redis instance, otherwise it must be left blank or not configured
```

## SQL Database (Microsoft, MySQL, MariaDB, PostgreSQL)

```
CLIPPYENABLE: true # optional defaults to true
HIDEINPUT: true # optional defaults to true
VAULTPWD: SuperStrongsecretPWD!
STORE: mysql #required. For MySQL and MariaDB use mysql, for PostgreSQL use postgres and mssql for Microsoft SQL
VALUECOLOR: blue # Optional defaults to red
DB: Vault #required, use correct value for your installation
HIDEINPUT: true # Optional, defaults to false
HOST: localhost # required, use correct hostname
DBUSER: script # required, use correct value for your installation
DBPWD: SecretDBPassword   # Required
```

