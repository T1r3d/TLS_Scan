# TLS_Scan
**A TLS Scanner for collecting the HTTPS information(Course Assignment)** 

Only cipher suites and certificate are collected currently.

Update the ciphersuites.txt by runing the following command in your linux shell.

```sh -c "openssl ciphers -v | awk '{print $1}' > ciphersuites.txt"```

Env requirements:
- OpenSSL
- Python3

usage: tls_scan.py [-h] [-p PORT] [-v] target

positional arguments:
  target                The target domain name.

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  The port on which the HTTPS service is running.
  -v, --verbose         Enable the verbose log.
