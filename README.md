# TLS_Scan
A TLS Scanner for collecting the HTTPS information(Course Assignment) 

Only cipher suites and certificate are collected currently.

Update the ciphersuites.txt by runing `sh -c "openssl ciphers -v | awk '{print $1}' > ciphersuites.txt"` in your linux shell.

Env requirement:
    OpenSSL
    Python3