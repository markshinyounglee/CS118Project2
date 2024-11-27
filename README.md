# CS 118 Fall 24 Project 2

# Notes
You only need to modify sec.c and fix input_sec() and output_sec().

# DO THIS BEFORE SUBMISSION
- delete -L/usr/local/openssl/lib64 (unique for my Debian machine)
- change load_ca_public_key("./keys/ca_public_key.bin"); to load_ca_public_key("ca_public_key.bin"); and do the same for all init_io() key load calls.

This repository contains the solution to Project 1. It also has extra code that serves as the baseline to Project 2.

`security.c` and `security.h` are wrappers around OpenSSL 3's `libcrypto` library. Any of the complicated cryptography mechanics have already been implemented for you. Feel free to read their descriptions in `security.h`. When submitting, make sure to add these files to your Makefile and your ZIP file.

In the `keys` directory, you'll see the files mentioned by the spec. Place these in the current working directory of wherever you're testing. For example, if you run `./client` and your PWD is `/Users/eado`, make sure `ca_public_key.bin` exists in `/Users/eado`. Note that the autograder automatically generates these files--do not rely on the exact contents of them. Read the [spec](https://docs.google.com/document/d/1FmEiFnYRwgBep5xgdoXmsTbzCaiUmznaYc6W-SHPtCs) for more info.


# Environment Debugging Notes

I added this flag to gcc to work during compilation:
$ -L/usr/local/openssl/lib64 
I should delete this from Makefile before submission
(tell the linker to look for libcrypto.a and libcrypto.so under /usr/local/openssl)
Source: https://stackoverflow.com/questions/5593284/undefined-reference-to-ssl-library-init-and-ssl-load-error-strings

Use sudo ldconfig /usr/local/lib64 to fix dynamic library linking issues
```shell
$ openssl version
openssl: error while loading shared libraries: libssl.so.3: cannot open shared object file: No such file or directory
$ sudo ldconfig /usr/local/lib64
$ openssl version
OpenSSL 3.4.0 22 Oct 2024 (Library: OpenSSL 3.4.0 22 Oct 2024)
```

We must also check that the application is first searching for openssl in /usr/local/bin rather than /usr/bin
https://unix.stackexchange.com/questions/432023/how-to-force-use-openssl-from-usr-local



