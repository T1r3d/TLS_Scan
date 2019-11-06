# TLS_Scan
A TLS Scanner for collecting the HTTPS information(Course Assignment) 

Only cipher suites and certificate are collected currently.

Update the ciphersuites.txt by runing the following command in your linux shell.
```sh -c "openssl ciphers -v | awk '{print $1}' > ciphersuites.txt"```

Env requirement:
- OpenSSL
- Python3