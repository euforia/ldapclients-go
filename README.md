ldapclients-go
--------------
Wrapper library to handle basic ldap based auth.

Currently basic ldap and AD are implemented.


Installation
------------

go get github.com/euforia/ldapclients-go


Usage
-----
```
import "github.com/euforia/ldapclients-go"

client, err := NewActiveDirectoryClient(uri, bind_dn, bind_pass, search_base)

// OR

client, err := NewActiveDirectoryClient(uri, bind_dn, bind_pass)

// Optionally enable caching using the default TTL
client.EnableCaching(0)

// Auth a user with a password
client.Authenticate(username, password)
```