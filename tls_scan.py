#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""A TLS information scanner.(Only cipher suites and certificates are collected currently.)"""

__author__ = "t1r3d"

import argparse
import socket
import ssl
import pprint

# Init the SSLContext.
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
context.load_default_certs()

# Load the cipher suites
with open("ciphersuites.txt", "rt") as f:
    cipher_suites = [c.strip() for c in f.readlines()]

def tls_scan(target, port=443, cipher_suites=cipher_suites, verbose=False):
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
        with socket.create_connection((target, port)) as sock:
            with context.wrap_socket(sock, server_hostname=target,  do_handshake_on_connect=False) as ssock:
                try:
                    ssock.do_handshake()
                    support_cipher_suites.append(cipher_suite)
                    if verbose:
                        print("\033[1;32;40m[+]\033[0m %s supported."%cipher_suite)
                except ssl.SSLError as e:
                    if verbose:
                        print("\033[1;33m[-]\033[0m %s not supported!"%cipher_suite)
    result["support_cipher_suites"] = support_cipher_suites
    result["certificate"] = ssl.get_server_certificate((target, port))
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


def init():
    """Init the argsparser.

    Return:
        Argument Object.
    """
    parser = argparse.ArgumentParser(description="A TLS information scanner.(Only cipher suites and certificates are collected currently.)")
    parser.add_argument("-p", "--port", dest="port", help="The port on which the HTTPS service is running.")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable the verbose log.")
    parser.add_argument("target", help="The target domain name.")
    args = parser.parse_args()

    return args


def main():
    banner()
    args = init()
    target = args.target
    print("\033[1;32;40m[*]\033[0m Scan Start.")
    if args.port and args.verbose:
        port = args.port
        verbose = args.verbose
        result = tls_scan(target, port=port, verbose=verbose)
    elif args.port:
        port = args.port
        result = tls_scan(target, port=port)
    else:
        verbose = args.verbose
        result = tls_scan(target, verbose=verbose)
    result = tls_scan(target)
    print("\033[1;32;40m[*]\033[0m Scan Finished.")
    print("\033[1;32;40m[+]\033[0m Result Follwing.")
    pprint.pprint(result)


if __name__ == "__main__":
    main()

# TODO(t1r3d): Add more commandline options(-c ciphersuites, -o outputfile), Enable the multi-target mode.