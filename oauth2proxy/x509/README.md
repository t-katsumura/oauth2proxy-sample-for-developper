## How to create certification using OpenSSL

Run command

```
openssl req -x509 -nodes -days 365000 -newkey rsa:4096 -keyout tls.key -out tls.crt -subj "/CN=oauth2proxy"
```
