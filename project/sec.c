#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>  // debugging

#include "consts.h"
#include "io.h"
#include "security.h"

int state_sec = 0;              // Current state for handshake
uint8_t nonce[NONCE_SIZE];      // Store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // Store peer's nonce to sign

void init_sec(int initial_state) {
    state_sec = initial_state;
    init_io();  // set stdin and stdout as nonblocking

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        generate_private_key(); 
        derive_public_key(); 
        derive_self_signed_certificate(); 
        load_ca_public_key("../keys/ca_public_key.bin"); 
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) { 
        load_certificate("../keys/server_cert.bin"); 
        load_private_key("../keys/server_key.bin"); 
        derive_public_key(); 
    } 
    generate_nonce(nonce, NONCE_SIZE);
}

// use memcpy() to load data to the buffer
// this implements a FSM (finite state machine)
// TODO: put something into the buffer
ssize_t input_sec(uint8_t* buf, size_t max_length) {
    // This passes it directly to standard input (working like Project 1)
    // return input_io(buf, max_length);

    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");

        /* Insert Client Hello sending logic here */
        // these all go into the payload
        // instead of reading from stdin, we need authentication
        // first bit is NONCE_CLIENT_HELLO
        // second two bits are NONCE_SIZE
        // and the remaining 32 bits are nonce
        int nonce_total_size = TLV_maker(buf, NONCE_CLIENT_HELLO, NONCE_SIZE, nonce);
        assert(nonce_total_size == 35);
        int load_size = TLV_maker(buf, CLIENT_HELLO, nonce_total_size, buf);
        
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return load_size;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        /* Insert Server Hello sending logic here */
        // server nonce
        uint8_t* nonce_buf;
        int nonce_size = TLV_maker(nonce_buf, NONCE_SERVER_HELLO, NONCE_SIZE, nonce);
        
        // certificate
        // size: cert_size, buffer: certificate
        uint8_t* cert_buf;
        load_certificate("../keys/server_cert.bin");
        int certificate_size = TLV_maker(cert_buf, CERTIFICATE, cert_size, certificate);

        // nonce signature 
        uint8_t* nonce_sign_buf;
        uint8_t* nonce_signature;
        int sign_size = sign(peer_nonce, NONCE_SIZE, nonce_signature); 
        int signature_size = TLV_maker(nonce_sign_buf, NONCE_SIGNATURE_SERVER_HELLO, sign_size, nonce_signature);
        
        // put everything in load before writing to buffer
        uint8_t* load;
        memcpy(load, nonce_buf, nonce_size);
        memcpy(load+nonce_size, cert_buf, certificate_size);
        memcpy(load+nonce_size+certificate_size, signature_size, nonce_sign_buf);
        int total_size = nonce_size + certificate_size + signature_size;

        // write to buf
        int load_size = TLV_maker(buf, SERVER_HELLO, total_size, load);

        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return load_size;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND: {
        print("SEND KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request sending logic here */

        state_sec = CLIENT_FINISHED_AWAIT;
        return 0;
    }
    case SERVER_FINISHED_SEND: {
        print("SEND FINISHED");

        /* Insert Finished sending logic here */

        state_sec = DATA_STATE;
        return 0;
    }
    case DATA_STATE: {
        /* Insert Data sending logic here */

        // PT refers to the amount you read from stdin in bytes
        // CT refers to the resulting ciphertext size
        // fprintf(stderr, "SEND DATA PT %ld CT %lu\n", stdin_size, cip_size);

        return 0;
    }
    default:
        return 0;
    }
}

// TODO: write content of buffer to STDOUT or something
void output_sec(uint8_t* buf, size_t length) {
    // This passes it directly to standard output (working like Project 1)
    // return output_io(buf, length);

    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        if (*buf != CLIENT_HELLO)
            exit(4);

        print("RECV CLIENT HELLO");

        /* Insert Client Hello receiving logic here */
        // put client nonce into peer_nonce

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        if (*buf != SERVER_HELLO)
            exit(4);

        print("RECV SERVER HELLO");

        /* Insert Server Hello receiving logic here */
        int peer_cert_loc = find_location(buf, state_sec, CERTIFICATE);
        uint16_t peer_cert_size = cert_buf[peer_cert_loc - 2] << 1 + buf[peer_cert_loc - 1];
        int peer_pubkey_loc = find_location(buf, state_sec, PUBLIC_KEY);
        uint16_t peer_pubkey_size = cert_buf[peer_pubkey_loc - 2] << 1 + buf[peer_pubkey_loc - 1];

        // 1. verify that certificate was signed by CA
        int status = verify(
            &buf[peer_cert_loc],  // certificate from CA
            peer_cert_size, 
            &buf[peer_pubkey_loc],  // public key of server
            peer_pubkey_size, 
            ec_ca_public_key
        );
        if (status != 1)
        {
            print("Server Public Key Verification failed");
            exit(1);
        }

        // 2. verify that client nonce was signed by the server
        int peer_nonce_sign_loc = find_location(buf, state_sec, NONCE_SERVER_HELLO);
        uint16_t peer_nonce_sign_size = cert_buf[peer_nonce_sign_loc - 2] << 1 + buf[peer_nonce_sign_loc - 1];
        status = verify(
            &buf[peer_nonce_sign_loc], // server nonce
            peer_nonce_sign_size, 
            nonce, // client nonce
            NONCE_SIZE,
            &buf[peer_pubkey_loc]
        );
        if (status != 1)
        {
            print("Server Nonce Signature Verification failed");
            exit(2);
        }

        // put server nonce into peer_nonce
        int peer_nonce_loc = find_location(buf, state_sec, NONCE_SERVER_HELLO);
        memcpy(&buf[peer_nonce_loc], peer_nonce, NONCE_SIZE);

        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT: {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request receiving logic here */
        // after key exchange request, load peer public key from data
        // load_peer_public_key(ec_peer_public_key, (get public key from data section));

        state_sec = SERVER_FINISHED_SEND;
        break;
    }
    case CLIENT_FINISHED_AWAIT: {
        if (*buf != FINISHED)
            exit(4);

        print("RECV FINISHED");

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        if (*buf != DATA)
            exit(4);

        /* Insert Data receiving logic here */

        // PT refers to the resulting plaintext size in bytes
        // CT refers to the received ciphertext size
        // fprintf(stderr, "RECV DATA PT %ld CT %hu\n", data_len, cip_len);
        break;
    }
    default:
        break;
    }
}

uint32_t TLV_maker(uint8_t* buf, uint8_t type, uint16_t length, uint8_t* value)
{   
    uint32_t load_size = length + 3;  // T (1B) + L (2B) + V (NONCE_SIZE)
    uint8_t load[load_size];
    load[0] = type;  // type is 1 byte
    load[1] = length >> 8; // length is 2 bytes
    load[2] = length;
    memcpy(load+3, value, length); // value is arbitary length
    memcpy(buf, load, load_size);
    return load_size;
}

// TODO: implement a function that searches 
// for the location of the data
// e.g. location of certificate buffer
int find_location(uint8_t* data, int state_sec, uint8_t type)
{
    switch(state_sec)
    {
        case SERVER_CLIENT_HELLO_AWAIT:
        case CLIENT_SERVER_HELLO_AWAIT:
        case SERVER_KEY_EXCHANGE_REQUEST_AWAIT:
        case CLIENT_FINISHED_AWAIT:
        case DATA_STATE:
    }
    return 0;
}