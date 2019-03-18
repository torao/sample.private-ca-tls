# セキュア通信

プライベート CA を立て、その CA によって発行された証明書を使ってサーバとクライアントが SSL/TLS 通信を行うサンプル。

## 秘密鍵と証明書の作成

プライベート CA の秘密鍵 (PKCS#8 形式) と X.509 証明書を ECDSA アルゴリズムで作成する。

```
$ mkdir ca
$ cd ca
$ openssl ecparam -out cakey.pem -name prime256v1 -genkey
$ openssl req -new -key cakey.pem -sha256 -subj "/C=JP/ST=Tokyo/O=Example Ltd./OU=Dev 1 Division/CN=example.com" -out cacsr.pem
$ openssl x509 -req -days 3650 -in cacsr.pem -signkey cakey.pem -out cacert.
$ openssl pkcs8 -topk8 -inform PEM -outform DER -in cakey.pem -nocrypt -out cakey.pk8

$ mkdir demoCA
$ echo 00 > demoCA/serial
$ touch demoCA/index.txt
```

サーバ証明書を作成。

```
$ openssl ecparam -out serverkey.pem -name prime256v1 -genkey
$ openssl req -new -key serverkey.pem -sha256 -subj "/C=JP/ST=Tokyo/O=Server Ltd./OU=Server1/CN=server.com" -out servercsr.pem
$ $ openssl ca -keyfile cakey.pem -cert cacert.pem -in servercsr.pem -out servercert.pem -days 3650 -config <(cat openssl.cnf <(printf "\n[usr_cert]\nsubjectAltName=DNS:server.com,DNS:foo.server.com"))
$ openssl pkcs8 -topk8 -inform PEM -outform DER -in serverkey.pem -nocrypt -out serverkey.pk8
```

同様にクライアント証明書を作成。

```
$ openssl ecparam -out clientkey.pem -name prime256v1 -genkey
$ openssl req -new -key clientkey.pem -sha256 -subj "/C=JP/ST=Tokyo/O=Client Ltd./OU=Client1/CN=client.com" -out clientcsr.pem
$ openssl ca -keyfile cakey.pem -cert cacert.pem -in clientcsr.pem -out clientcert.pem -days 3650 -config <(cat openssl.cnf <(printf "\n[usr_cert]\nsubjectAltName=DNS:client.com,DNS:bar.client.com"))
$ openssl pkcs8 -topk8 -inform PEM -outform DER -in clientkey.pem -nocrypt -out clientkey.pk8
```