#include <unistd.h>
#include <stdio.h>

#include "security.h"

int main() {
    /* Server side */

    // Load server private key from file
    load_private_key("../keys/priv_key.bin");

    // Load client public key (typically over the network)
    int size;
    FILE* fp = fopen("../keys/client_pub_key.bin", "r");
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    char der[size];
    fseek(fp, 0, 0);
    fread(der, size, 1, fp);
    load_peer_public_key(der, size);

    // Derive ECDH secret
    derive_secret();

    // Plaintext for encryption
    char data[] = "Hello world";
    printf("Plaintext: %.*s %d\n", sizeof(data), data, sizeof(data));

    // Encrypt plaintext
    char cipher[3000];
    char iv[16];
    size_t cipher_size = encrypt_data(data, sizeof(data), iv, cipher, 0);
    printf("Ciphertext: %.*s %d\n", (int) cipher_size, cipher, cipher_size);

    // Decrypt ciphertext
    char decrypted_data[3000];
    size_t data_size = decrypt_cipher(cipher, cipher_size, iv, decrypted_data, 0);
    printf("Decrypted plaintext: %.*s %d\n", (int) data_size, decrypted_data, data_size);

    clean_up();

    return 0;
}