#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "consts.h"
#include "io.h"
#include "security.h"

int state_sec = 0;              // Current state for handshake
uint8_t nonce[NONCE_SIZE];      // Store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // Store peer's nonce to sign
bool inc_mac = false;           // For testing only: send incorrect MACs

void insert_type(uint8_t** buf, uint8_t type) {
    memcpy(*buf, &type, 1);
    *buf += 1;
}

void insert_length(uint8_t** buf, uint16_t length) {
    length = htons(length);
    memcpy(*buf, &length, 2);
    *buf += 2;
}

void init_sec(int initial_state, bool bad_mac) {
    state_sec = initial_state;
    inc_mac = bad_mac;
    init_io();

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

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    uint8_t* buffer = buf;

    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");

        // Insert type and length for message
        insert_type(&buffer, CLIENT_HELLO);
        insert_length(&buffer, NONCE_SIZE + 3);

        // Insert type and length for nonce
        insert_type(&buffer, NONCE_CLIENT_HELLO);
        insert_length(&buffer, NONCE_SIZE);

        // Copy nonce into buffer
        memcpy(buffer, nonce, NONCE_SIZE);
        buffer += NONCE_SIZE;

        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return buffer - buf;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        // Insert type for message
        insert_type(&buffer, SERVER_HELLO);

        // Don't know total length yet
        buffer += 2;
        uint8_t* msg_buf = buffer; // Save to calculate total length

        // Insert type and length for nonce
        insert_type(&buffer, NONCE_SERVER_HELLO);
        insert_length(&buffer, NONCE_SIZE);

        // Copy nonce into buffer
        memcpy(buffer, nonce, NONCE_SIZE);
        buffer += NONCE_SIZE;

        // Copy certificate into buffer
        memcpy(buffer, certificate, cert_size);
        buffer += cert_size;

        // Insert type for signature
        insert_type(&buffer, NONCE_SIGNATURE_SERVER_HELLO);

        // Don't know total length yet
        uint16_t* sig_len =
            (uint16_t*) buffer; // Save to calculate total length
        buffer += 2;

        // Sign nonce and place into buffer
        size_t sig_size = sign(peer_nonce, NONCE_SIZE, buffer);
        buffer += sig_size;

        // Set length of signature
        *sig_len = htons((uint16_t) sig_size);

        // Set length of whole message
        uint16_t* msg_len = (uint16_t*) (msg_buf - 2);
        *msg_len = htons((uint16_t) (buffer - msg_buf));

        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return buffer - buf;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND: {
        print("SEND KEY EXCHANGE REQUEST");

        // Insert type for message
        insert_type(&buffer, KEY_EXCHANGE_REQUEST);

        // Don't know total length yet
        buffer += 2;
        uint8_t* msg_buf = buffer; // Save to calculate total length

        // Copy certificate into buffer
        memcpy(buffer, certificate, cert_size);
        buffer += cert_size;

        // Insert type for signature
        insert_type(&buffer, NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST);

        // Don't know total length yet
        uint16_t* sig_len =
            (uint16_t*) buffer; // Save to calculate total length
        buffer += 2;

        // Sign nonce and place into buffer
        size_t sig_size = sign(peer_nonce, NONCE_SIZE, buffer);
        buffer += sig_size;

        // Set length of signature
        *sig_len = htons((uint16_t) sig_size);

        // Set length of whole message
        uint16_t* msg_len = (uint16_t*) (msg_buf - 2);
        *msg_len = htons((uint16_t) (buffer - msg_buf));

        state_sec = CLIENT_FINISHED_AWAIT;
        return buffer - buf;
    }
    case SERVER_FINISHED_SEND: {
        print("SEND FINISHED");

        // Insert type and length for finished
        insert_type(&buffer, FINISHED);
        insert_length(&buffer, 0);

        state_sec = DATA_STATE;
        return buffer - buf;
    }
    case DATA_STATE: {
        // Insert type for message
        insert_type(&buffer, DATA);

        // Don't know total length yet
        buffer += 2;
        uint8_t* msg_buf = buffer; // Save to calculate total length

        // Set IV type and size
        insert_type(&buffer, INITIALIZATION_VECTOR);
        insert_length(&buffer, IV_SIZE);
        uint8_t* iv_buf = buffer; // Save for IV insertion
        buffer += IV_SIZE;

        // Get appropriate amount of data to encrypt
        size_t plaintext_size =
            ((max_length - PLAINTEXT_OFFSET) / IV_SIZE) * IV_SIZE - 1;
        uint8_t plaintext[plaintext_size];
        ssize_t stdin_size = input_io(plaintext, plaintext_size);

        // Don't send anything if not available
        if (stdin_size <= 0)
            return 0;

        // Set Ciphertext type
        insert_type(&buffer, CIPHERTEXT);
        // Don't know total length yet
        uint16_t* cip_len =
            (uint16_t*) buffer; // Save to calculate total length
        buffer += 2;

        // Encrypt data and set length
        size_t cip_size =
            encrypt_data(plaintext, stdin_size, iv_buf, buffer);
        *cip_len = htons((uint16_t) cip_size);

        // Concat IV and ciphertext
        uint8_t data[IV_SIZE + cip_size];
        memcpy(data, iv_buf, IV_SIZE);
        memcpy(data + IV_SIZE, buffer, cip_size);
        buffer += cip_size;

        // Set MAC type and length
        insert_type(&buffer, MESSAGE_AUTHENTICATION_CODE);
        insert_length(&buffer, MAC_SIZE);
        hmac(data, IV_SIZE + cip_size, buffer);

        // For testing only: insert bad data in MAC
        if (inc_mac)
            buffer[10] = 0;

        buffer += MAC_SIZE;

        // Set length of whole message
        uint16_t* msg_len = (uint16_t*) (msg_buf - 2);
        *msg_len = htons((uint16_t) (buffer - msg_buf));

        fprintf(stderr, "SEND DATA PT %ld CT %lu\n", stdin_size, cip_size);

        return buffer - buf;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    print_tlv(buf, length);
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        if (*buf != CLIENT_HELLO)
            exit(4);

        print("RECV CLIENT HELLO");

        // Save peer nonce
        memcpy(peer_nonce, buf + 6, NONCE_SIZE);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        if (*buf != SERVER_HELLO)
            exit(4);

        print("RECV SERVER HELLO");

        // Save peer nonce
        buf += 6;
        memcpy(peer_nonce, buf, NONCE_SIZE);
        buf += NONCE_SIZE;

        // Verify certificate
        buf += 4;
        uint16_t pub_key_len = ntohs(*(uint16_t*) buf);
        buf += 2;
        uint8_t* pub_key = buf;
        buf += pub_key_len;
        buf += 1;
        uint16_t sig_key_len = ntohs(*(uint16_t*) buf);
        buf += 2;
        uint8_t* sig_key = buf;
        if (verify(pub_key, pub_key_len, sig_key, sig_key_len,
                   ec_ca_public_key) != 1)
            exit(1);
        buf += sig_key_len;

        // Load peer public key and perform DH and keygen
        load_peer_public_key(pub_key, pub_key_len);
        derive_secret();
        derive_keys();

        // Verify nonce
        buf += 1;
        uint16_t nonce_sig_len = ntohs(*(uint16_t*) buf);
        buf += 2;

        if (verify(nonce, NONCE_SIZE, buf, nonce_sig_len, ec_peer_public_key) !=
            1)
            exit(2);

        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT: {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        // Load certificate
        buf += 7;
        uint16_t pub_key_len = ntohs(*(uint16_t*) buf);
        buf += 2;
        uint8_t* pub_key = buf;
        buf += pub_key_len;

        // Load peer public key and perform DH and keygen
        load_peer_public_key(pub_key, pub_key_len);
        derive_secret();
        derive_keys();

        // Verify cert
        buf += 1;
        uint16_t sig_key_len = ntohs(*(uint16_t*) buf);
        buf += 2;
        uint8_t* sig_key = buf;
        if (verify(pub_key, pub_key_len, sig_key, sig_key_len,
                   ec_peer_public_key) != 1)
            exit(1);
        buf += sig_key_len;

        // Verify nonce
        buf += 1;
        uint16_t nonce_sig_len = ntohs(*(uint16_t*) buf);
        buf += 2;
        if (verify(nonce, NONCE_SIZE, buf, nonce_sig_len, ec_peer_public_key) !=
            1)
            exit(2);

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

        // Get IV
        buf += 6;
        uint8_t* iv = buf;

        // Get Ciphertext and length
        buf += IV_SIZE + 1;
        uint16_t cip_len = ntohs(*(uint16_t*) buf);
        buf += 2;
        uint8_t* ciphertext = buf;
        buf += cip_len;

        // Get hmac
        buf += 3;
        uint8_t* hmac_other = buf;

        // Concat into buffer
        uint8_t data[IV_SIZE + cip_len];
        memcpy(data, iv, IV_SIZE);
        memcpy(data + IV_SIZE, ciphertext, cip_len);

        // Calculate HMAC
        uint8_t hmac_calc[MAC_SIZE];
        hmac(data, IV_SIZE + cip_len, hmac_calc);

        // Compare HMAC
        if (memcmp(hmac_other, hmac_calc, MAC_SIZE) != 0)
            exit(3);

        // Decrypt data and output
        size_t data_len = decrypt_cipher(ciphertext, cip_len, iv, data);
        output_io(data, data_len);

        fprintf(stderr, "RECV DATA PT %ld CT %hu\n", data_len, cip_len);
        break;
    }
    default:
        break;
    }
}
