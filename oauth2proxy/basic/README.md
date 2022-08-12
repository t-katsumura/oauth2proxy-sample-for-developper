## How to create basic auth user

Currently oauth2-proxy support `sha1` and `bcrypt` algorithm for htpasswd file.  
To make allowed user for basic authentication, write userinfo in `htpasswd.txt` in the following format.

```
<username>:<encrypted password>
```

See. https://github.com/oauth2-proxy/oauth2-proxy/blob/master/pkg/authentication/basic/htpasswd.go


**example for bcrypt**

This makes a user of `basicuserB:password`.  
Encrypted password must has one of `$2a"`, `$2b$`, `$2x$`, `$2y$` prefix. 

```
basicuserB:$2y$08$1VrI4R2MvqYQb3BMnnA7IeQ1.KyoKtqLT6XDIKPNRlB2/aA.PI8ZW
```

You can use online tools like

- https://bcrypt-generator.com/
- https://bcrypt.online/
- https://www.devglan.com/online-tools/bcrypt-hash-generator


**example for sha1**

This makes a user of `basicuserA:password`.  
Encrypted password must has `{SHA}` prefix. 

```
basicuserA:{SHA}5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
```

You can use online tools like

- http://www.sha1-online.com/
- https://emn178.github.io/online-tools/sha1.html
- https://md5decrypt.net/en/Sha1/


