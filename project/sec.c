#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // memset()
#include <unistd.h>
#include <assert.h>  // debugging

#include "consts.h"
#include "io.h"
#include "security.h"
#include "sec.h"

#define BYTE_SIZE 8
#define TYPE_SIZE 1
#define LENGTH_SIZE 2

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
        load_ca_public_key("./keys/ca_public_key.bin"); 
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) { 
        load_certificate("./keys/server_cert.bin"); 
        load_private_key("./keys/server_key.bin"); 
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
        uint8_t* load = (uint8_t*) malloc(NONCE_SIZE + 3);
        int nonce_total_size = TLV_maker(load, NONCE_CLIENT_HELLO, NONCE_SIZE, nonce);
        
        assert(nonce_total_size == 35);
        int load_size = TLV_maker(buf, CLIENT_HELLO, nonce_total_size, load);
        
        print_tlv(buf, load_size);

        free(load);

        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return load_size;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        /* Insert Server Hello sending logic here */
        // server nonce
        uint8_t* nonce_buf = (uint8_t*) malloc(NONCE_SIZE + 3);
        int nonce_size = TLV_maker(nonce_buf, NONCE_SERVER_HELLO, NONCE_SIZE, nonce);
        
        // certificate
        // load_certificate() already called
        // size: cert_size, buffer: certificate
        uint8_t* cert_buf = (uint8_t*) malloc(cert_size + 3);
        int certificate_size = TLV_maker(cert_buf, CERTIFICATE, cert_size, certificate);

        // nonce signature 
        uint8_t* nonce_signature = (int8_t*) malloc(255);
        int sign_size = sign(peer_nonce, NONCE_SIZE, nonce_signature); 
        uint8_t* nonce_sign_buf = (uint8_t*) malloc(sign_size + 3);
        fprintf(stderr, "signature size: %d\n", sign_size);
        int signature_size = TLV_maker(nonce_sign_buf, NONCE_SIGNATURE_SERVER_HELLO, sign_size, nonce_signature);
        
        // put everything in load before writing to buffer
        int total_size = nonce_size + certificate_size + signature_size;
        uint8_t* load = (uint8_t*) malloc(total_size);
        memcpy(load, nonce_buf, nonce_size);
        memcpy(load+nonce_size, cert_buf, certificate_size);
        memcpy(load+nonce_size+certificate_size, nonce_sign_buf, signature_size);
    
        // write to buf
        int load_size = TLV_maker(buf, SERVER_HELLO, total_size, load);

        print_tlv(buf, load_size);

        free(nonce_buf);
        free(cert_buf);
        free(nonce_sign_buf);
        free(load);

        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return load_size;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND: {
        print("SEND KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request sending logic here */
        // cert_size and certificate are global variables
        derive_self_signed_certificate();
        // my own code commented out:
        // uint8_t raw_key_buf[0];
        // int key_size = TLV_maker(raw_key_buf, PUBLIC_KEY, pub_key_size, public_key);
        // uint8_t signed_key_buf[0];
        // int self_signed_key_size = sign(public_key, pub_key_size, signed_key_buf);
        // self_signed_key_size = TLV_maker(signed_key_buf, SIGNATURE, self_signed_key_size, signed_key_buf);
        // uint8_t load[0];
        // memcpy(load, raw_key_buf, key_size);
        // memcpy(load+key_size, signed_key_buf, self_signed_key_size);
        // int load_size = self_signed_key_size + key_size;

        // uint8_t cert_buf[0];
        // int certificate_size = TLV_maker(cert_buf, CERTIFICATE, total_size, load);
        
        // sign server's nonce with client's private key
        uint8_t* nonce_signature = (uint8_t*) malloc(255);
        int signature_size = sign(peer_nonce, NONCE_SIZE, nonce_signature);
        uint8_t* nonce_sign_buf = (uint8_t*) malloc(signature_size + 3);
        int sign_buf_size = TLV_maker(nonce_sign_buf, NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST, signature_size, nonce_signature);

        int load_size = cert_size + sign_buf_size;
        uint8_t* load = (uint8_t*) malloc(load_size);
        memcpy(load, certificate, cert_size);
        memcpy(load+cert_size, nonce_sign_buf, sign_buf_size);

        // write to buf
        load_size = TLV_maker(buf, KEY_EXCHANGE_REQUEST, load_size, load);

        print_tlv(buf, load_size);

        free(nonce_signature);
        free(nonce_sign_buf);
        free(load);

        state_sec = CLIENT_FINISHED_AWAIT;
        return load_size;
    }
    case SERVER_FINISHED_SEND: {
        print("SEND FINISHED");

        /* Insert Finished sending logic here */
        // send a finish packet
        char empty[1] = {0};
        int finish_packet_size = TLV_maker(buf, FINISHED, 0, empty);

        print_tlv(buf, finish_packet_size);
        state_sec = DATA_STATE;

        return finish_packet_size;
    }
    case DATA_STATE: {
        /* Insert Data sending logic here */

        // PT refers to the amount you read from stdin in bytes
        // CT refers to the resulting ciphertext size
        // fprintf(stderr, "SEND DATA PT %ld CT %lu\n", stdin_size, cip_size);
        int max_data_len = plaintxt_length(max_length);
        uint8_t* data = (uint8_t*) malloc(max_data_len);
        int data_size = input_io(data, max_data_len);
        if (data_size <= 0)
        {
            break; // nothing read
        }


        uint8_t *iv, *ciphertext, *digest;
        iv = (uint8_t*) malloc(IV_SIZE + 3);
        ciphertext = (uint8_t*) malloc(MAX_PAYLOAD); // TODO: sufficiently big size
        digest = (uint8_t*) malloc(MAC_SIZE + 3);

        // iv is fixed as 16 bytes
        // populate iv and cypertext
        int ciphertext_size = encrypt_data(data, data_size, iv, ciphertext);
        // get an HMAC SHA-256 digest of data
        uint8_t* iv_cipher = (uint8_t*) malloc(IV_SIZE + ciphertext_size);
        memcpy(iv_cipher, iv, IV_SIZE);
        memcpy(iv_cipher, ciphertext, ciphertext_size); 
        hmac(iv_cipher, data_size, digest);

        // create TLV packets for each component
        int iv_size = TLV_maker(iv, INITIALIZATION_VECTOR, IV_SIZE, iv);
        ciphertext_size = TLV_maker(ciphertext, CIPHERTEXT, ciphertext_size, ciphertext);
        int digest_size = TLV_maker(digest, MESSAGE_AUTHENTICATION_CODE, MAC_SIZE, digest);

        int load_size = iv_size + ciphertext_size + digest_size;
        uint8_t* load = (uint8_t*) malloc(load_size);
        memcpy(load, iv, iv_size);
        memcpy(load+iv_size, ciphertext, ciphertext_size);
        memcpy(load+iv_size+ciphertext_size, digest, digest_size);
        load_size = TLV_maker(buf, DATA, load_size, load);
        // Macros for reference
        // #define DATA 0x40
        // #define INITIALIZATION_VECTOR 0x41
        // #define CIPHERTEXT 0x42
        // #define MESSAGE_AUTHENTICATION_CODE 0x43

        free(data);
        free(iv);
        free(ciphertext);
        free(iv_cipher);
        free(digest);

        print_tlv(buf, load_size);
        return load_size;
    }
    default:
        return 0;
    }
}

// TODO: write content of buffer to STDOUT or something
void output_sec(uint8_t* buf, size_t length) {
    // This passes it directly to standard output (working like Project 1)
    // return output_io(buf, length);
    print_tlv(buf, length);

    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        if (*buf != CLIENT_HELLO)
            exit(4);

        print("RECV CLIENT HELLO");

        /* Insert Client Hello receiving logic here */
        // put client nonce into peer_nonce
        int nonce_loc = find_location(buf, state_sec, NONCE_SIZE);

        memcpy(peer_nonce, &buf[nonce_loc], NONCE_SIZE);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        if (*buf != SERVER_HELLO)
            exit(4);

        print("RECV SERVER HELLO");

        /* Insert Server Hello receiving logic here */
        int peer_sign_loc = find_location(buf, state_sec, SIGNATURE);
        uint16_t peer_sign_size = get_size(buf, peer_sign_loc);
        int peer_pubkey_loc = find_location(buf, state_sec, PUBLIC_KEY);
        uint16_t peer_pubkey_size = get_size(buf, peer_pubkey_loc);

        // load server's public key as our peer key
        // now server public key is in 'ec_peer_public_key' for the server
        load_peer_public_key(&buf[peer_pubkey_loc], peer_pubkey_size);

        // 1. verify that certificate was signed by CA
        int status = verify(
            &buf[peer_pubkey_loc],  // public key of server
            peer_pubkey_size, 
            &buf[peer_sign_loc],  // certificate [signature] from CA
            peer_sign_size, 
            ec_ca_public_key // key to decrypt the certificate (authority)
        );
        if (status != 1)
        {
            print("Server Public Key Verification failed");
            exit(1);
        }

        // 2. verify that client nonce was signed by the server
        int peer_nonce_sign_loc = find_location(buf, state_sec, NONCE_SERVER_HELLO);
        uint16_t peer_nonce_sign_size = get_size(buf, peer_nonce_sign_loc);
        status = verify(
            nonce, // client nonce
            NONCE_SIZE,
            &buf[peer_nonce_sign_loc], // server nonce
            peer_nonce_sign_size, 
            ec_peer_public_key // authority (use server public key)
        );
        if (status != 1)
        {
            print("Server Nonce Signature Verification failed");
            exit(2);
        }

        // put server nonce into peer_nonce
        int peer_nonce_loc = find_location(buf, state_sec, NONCE_SERVER_HELLO);
        memcpy(&buf[peer_nonce_loc], peer_nonce, NONCE_SIZE);

        // generate ENC and MAC keys using HKDF
        // do this once you load the peer public key
        derive_secret();
        derive_keys();

        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT: {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        // 1. verify that the certificate was self-signed
        int client_sign_loc = find_location(buf, state_sec, SIGNATURE);
        int client_sign_size = get_size(buf, client_sign_loc);
        int client_key_loc = find_location(buf, state_sec, PUBLIC_KEY);
        int client_key_size = get_size(buf, client_key_loc);

        /* Insert Key Exchange Request receiving logic here */
        // load peer public key (in this case, server loads client's public key)
        load_peer_public_key(&buf[client_key_loc], client_key_size);

        int status = verify(
            &buf[client_key_loc], // raw data (client key)
            client_key_size,
            &buf[client_sign_loc],  // certificate (signature)
            client_sign_size, 
            ec_peer_public_key // authority (since it is self-signed, use client's own key)
        );
        if (status != 1)
        {
            print("Client certificate was not self-signed");
            exit(1);
        }

        // 2. verify that the server nonce was signed by the client
        int client_signed_nonce_loc = find_location(buf, state_sec, NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST);
        int client_signed_nonce_size = get_size(buf, client_signed_nonce_loc);
        status = verify(
            nonce, 
            NONCE_SIZE, 
            &buf[client_signed_nonce_loc], 
            client_signed_nonce_size,
            ec_peer_public_key
        );
        if (status != 1)
        {
            print("Server nonce not signed by the client");
            exit(2);
        }

        // generate ENC and MAC key from the shared secret
        // do this once you load the peer public key
        derive_secret();
        derive_keys();

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
        
        // decode and then write to stdout
        
        // take ONE packet out of the buffer
        // 1. Unpack the packet
        int cipher_loc = find_location(buf, state_sec, CIPHERTEXT);
        int cipher_size = get_size(buf, cipher_loc);
        int iv_loc = find_location(buf, state_sec, INITIALIZATION_VECTOR);
        // iv_size is fixed to IV_SIZE (consts.h)
        int mac_loc = find_location(buf, state_sec, MESSAGE_AUTHENTICATION_CODE);
        // mac_size is also fixed 

        // 2. check the digest and see if it matches with the decrypt_cipher
        // if not, exit
        // if matches, proceed to decryption
        uint8_t* digest = &buf[mac_loc];

        // concatenate ciphertext and IV to see if they match
        int cipher_iv_size = cipher_size + IV_SIZE;
        uint8_t* cipher_iv = (uint8_t*) malloc(cipher_iv_size);
        memcpy(cipher_iv, &buf[cipher_loc], cipher_size);
        memcpy(cipher_iv+cipher_size, &buf[iv_loc], IV_SIZE);
        hmac(cipher_iv, cipher_iv_size, digest);
        if (!memcmp(digest, &buf[mac_loc], MAC_SIZE)) // if two digests are different, exit
        {
            print("MAC values do not match!");
            exit(3);
        }

        // 3. Decrypt the ciphertext to plaintext 
        uint8_t* data = (uint8_t*) malloc(MAX_PAYLOAD); // TODO: sufficiently big size
        int data_size = decrypt_cipher(&buf[cipher_loc], cipher_size, &buf[iv_loc], data);

        // 4. write decrypted data to standard output
        output_io(data, data_size); 

        free(cipher_iv);
        free(data);
        
        break;
    }
    default:
        break;
    }
}

uint32_t TLV_maker(uint8_t* buf, uint8_t type, uint16_t length, uint8_t* value)
{   
    fprintf(stderr, "buf has %p\n", buf);
    if(buf == NULL)
    {
        exit(234);
    }
    print("TLV maker entered");
    uint32_t load_size = TYPE_SIZE + LENGTH_SIZE + length;  // T (1B) + L (2B) + V (NONCE_SIZE)
    uint8_t load[load_size];
    load[0] = type;  // type is 1 byte
    // how to copy int into byte array: https://community.intel.com/t5/Intel-Integrated-Performance/Convert-an-int-to-a-byte-array/td-p/888464
    uint16_t len = htons(length);
    memcpy(load+1, &len, sizeof(len)); // length in network should be big-endian
    print("length copied");
    memcpy(load+3, value, length); // value is arbitary length
    print("value copied");
    fprintf(stderr, "buf: %p, load: %p, load_size: %u\n", buf, load, load_size);
    fprintf(stderr, "bufsize: %lu\n", sizeof(buf));
    memcpy(buf, load, load_size);
    print("load copied");
    return load_size;
}

// function that searches for the index [location] of the data
// e.g. location of certificate buffer
// idea: check the type of data (*data) and see if it matches with type
// if yes, return that location + 3 (offset)
// else, retrieve the length and jump 
int find_location(uint8_t* data, int state_sec, uint8_t type)
{
    assert(state_sec == CLIENT_SERVER_HELLO_AWAIT 
            || state_sec == SERVER_CLIENT_HELLO_AWAIT
            || state_sec == SERVER_KEY_EXCHANGE_REQUEST_AWAIT 
            || state_sec == DATA_STATE);
    
    uint8_t* locator = data;
    int total_size = 0;
    while(1)
    {
        int currlen = locator - data + 3;
        if(*locator == type)
        {
            return currlen; // return the beginning index of field 
        }
        else if (total_size != 0 && currlen >= total_size) // maximum exceeded
        {
            break;
        }
        if(*locator == SERVER_HELLO 
            || *locator == CLIENT_HELLO
            || *locator == KEY_EXCHANGE_REQUEST 
            || *locator == DATA)
        {
            total_size = 3 + get_size(data, currlen);
            locator += 3; // jump to the payload
        }
        else
        {
            int jump = get_size(data, currlen);
            locator += jump;
        }
    }

    fprintf(stderr, "Finding location failed for %d in %d\n", state_sec, type);
    return 0;
}
// get size of the field
// location is found by find_location
uint16_t get_size(uint8_t* data, int bufloc) 
{
    return ntohs(*((uint16_t*) &data[bufloc-2])); // convert to little endian
}
// compute the max length of plain text that could be read at a time
uint16_t plaintxt_length(uint16_t payload_length)
{
    return ((payload_length - 60) / 16) * 16 - 1;
}