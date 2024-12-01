# CS 118 Fall 24 Project 2

# Notes
You only need to modify sec.c and fix input_sec() and output_sec().

# Run tests locally
Move keys under project folder and replace init_sec() in sec.c with
```shell
state_sec = initial_state;
init_io();  // set stdin and stdout as nonblocking

if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
    generate_private_key(); 
    derive_public_key(); 
    derive_self_signed_certificate(); 
    load_ca_public_key("./keys/ca_public_key.bin"); 
} else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) { 
    load_certificate("./keys/server_cert.bin"); 
    load_private_key("./keys/server_key.bin"); 
    derive_public_key(); 
} 
generate_nonce(nonce, NONCE_SIZE);
```

If you want to use refclient from docker:
Under /autograder/source/src in Docker, there is client and server. Copy those into submission folder and they will be populated in project folder.

# How TLS works
After the 3-way handshake for establishing TCP connection, we have additional handshake to exchange public keys between server and client. 
Exchanging the public keys and verifying that the keys are correct involves third-party certification authority which issues the certificate that the client can use
to verify that the public key holder is verified by the certification authority.
After the client and server exchange public key, they both use both keys to derive shared secret (ENC and MAC keys), which are in turn used to convert plain text into cypher text and IV. 


# Helpful debugging tips
- Using unittest to test individual functions helps a lot.
- Using print statements adroitly helps identify the region where the code fails.
- fsanitize=address helps identify where the memory leak is happening
- when in doubt (especially where the memory leak is happening), always print the pointer address. This helps identify where the memory is going out of bounds.
- make sure the types are properly declared (for instance, having uint16_t as the return type introduced many errors)
- use xxd to convert .bin to hexadecimal files, and then use `diff -u` to see the differences if test.bin and client.bin (or server.bin) differ.
- (not too recommended) strace --signal=SEGV could also be used but oftentimes it clogs up the code


# DO THIS BEFORE SUBMISSION
- delete -L/usr/local/openssl/lib64 (unique for my Debian machine)
- change load_ca_public_key("./keys/ca_public_key.bin"); to load_ca_public_key("ca_public_key.bin"); and do the same for all init_io() key load calls.

This repository contains the solution to Project 1. It also has extra code that serves as the baseline to Project 2.

`security.c` and `security.h` are wrappers around OpenSSL 3's `libcrypto` library. Any of the complicated cryptography mechanics have already been implemented for you. Feel free to read their descriptions in `security.h`. When submitting, make sure to add these files to your Makefile and your ZIP file.

In the `keys` directory, you'll see the files mentioned by the spec. Place these in the current working directory of wherever you're testing. For example, if you run `./client` and your PWD is `/Users/eado`, make sure `ca_public_key.bin` exists in `/Users/eado`. Note that the autograder automatically generates these files--do not rely on the exact contents of them. Read the [spec](https://docs.google.com/document/d/1FmEiFnYRwgBep5xgdoXmsTbzCaiUmznaYc6W-SHPtCs) for more info.


If you want to access src files, they are located in /autograder/source/src

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



