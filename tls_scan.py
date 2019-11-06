#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""A TLS information scanner.(Only cipher suites and certificates are collected currently.)"""

__author__ = "t1r3d"

import socket
import ssl
import pprint

# Init the SSLContext.
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
context.load_default_certs()


def tls_scan(target, cipher_suites):
    """Collect the cipher suites and certificates for a single target.
    
    Enumerate by controlling that every ClientHello message contains only one cipher suite.

    Args:
        target: The domain name of the scan target.
        cipher_suites: A list containing the cipher suites to probe.

    Return:
        A dict mapping keys to corresponding result. For example:

        {"support_cipher_suites": ('ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384'),
        "certificate": "certificate_string"}

    Raise:
        None
    """
    support_cipher_suites = []
    result = {}
    for cipher_suite in cipher_suites:
        context.set_ciphers(cipher_suite)
        with socket.create_connection((target, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target,  do_handshake_on_connect=False) as ssock:
                try:
                    ssock.do_handshake()
                    support_cipher_suites.append(cipher_suite)
                except ssl.SSLError as e:
                    print(e)
    result["support_cipher_suites"] = support_cipher_suites
    result["certificate"] = ssl.get_server_certificate((target, 443))
    return result
    

def banner():
    print(""" ________  __         ______         ______                                
/        |/  |       /      \       /      \                               
$$$$$$$$/ $$ |      /$$$$$$  |     /$$$$$$  |  _______   ______   _______  
   $$ |   $$ |      $$ \__$$/      $$ \__$$/  /       | /      \ /       \ 
   $$ |   $$ |      $$      \      $$      \ /$$$$$$$/  $$$$$$  |$$$$$$$  |
   $$ |   $$ |       $$$$$$  |      $$$$$$  |$$ |       /    $$ |$$ |  $$ |
   $$ |   $$ |_____ /  \__$$ |     /  \__$$ |$$ \_____ /$$$$$$$ |$$ |  $$ |
   $$ |   $$       |$$    $$/______$$    $$/ $$       |$$    $$ |$$ |  $$ |
   $$/    $$$$$$$$/  $$$$$$//      |$$$$$$/   $$$$$$$/  $$$$$$$/ $$/   $$/ 
                            $$$$$$/                                             Author: t1r3d
                            """)


def main():
    banner()
    target = "www.github.com"
    with open("ciphersuites.txt", "rt") as f:
        cipher_suites = [c.strip() for c in f.readlines()]
    print(cipher_suites)
    result = tls_scan(target, cipher_suites)
    pprint.pprint(result)


if __name__ == "__main__":
    main()