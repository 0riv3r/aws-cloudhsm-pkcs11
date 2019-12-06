/*
 * ofer.rivlin@cyberark.com
 */

#include <stdio.h>
#include "/home/ubuntu/pkcs11/aws-cloudhsm-pkcs11-examples/include/pkcs11/v2.40/cryptoki.h"
#include "aes.h"

/**
 * Encrypt and decrypt the encryption-service key using AES CBC.
 * @param session Active PKCS#11 session
 */
CK_RV aes_cbc_sample(CK_SESSION_HANDLE session, CK_BYTE_PTR plaintext) {
    CK_RV rv;

    // Generate a 256 bit AES key.
    CK_OBJECT_HANDLE aes_key = 6;
    // rv = generate_aes_key(session, 32, &aes_key);
    // if (CKR_OK != rv) {
    //     printf("AES key generation failed: %lu\n", rv);
    //     return rv;
    // }

    // CK_BYTE_PTR plaintext = "plaintext payload to encrypt";
    CK_ULONG plaintext_length = strlen(plaintext);

    printf("Plaintext: %s\n", plaintext);
    printf("Plaintext length: %lu\n", plaintext_length);

    // Prepare the mechanism 
    // The IV is hardcoded to all 0x01 bytes for this example.
    CK_BYTE iv[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    CK_MECHANISM mech = {CKM_AES_CBC_PAD, iv, 16};

    //**********************************************************************************************
    // Encrypt
    //**********************************************************************************************    

    rv = funcs->C_EncryptInit(session, &mech, aes_key);
    if (CKR_OK != rv) {
        printf("Encryption Init failed: %lu\n", rv);
        return rv;
    }

    // Determine how much memory will be required to hold the ciphertext.
    CK_ULONG ciphertext_length = 0;
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, NULL, &ciphertext_length);
    if (CKR_OK != rv) {
        printf("Encryption failed: %lu\n", rv);
        return rv;
    }

    // Allocate the required memory.
    CK_BYTE_PTR ciphertext = malloc(ciphertext_length);
    if (NULL == ciphertext) {
        printf("Could not allocate memory for ciphertext\n");
        return rv;
    }
    memset(ciphertext, 0, ciphertext_length);
    CK_BYTE_PTR decrypted_ciphertext = NULL;

    // Encrypt the data.
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, ciphertext, &ciphertext_length);
    if (CKR_OK != rv) {
        printf("Encryption failed: %lu\n", rv);
        goto done;
    }

    // Print just the ciphertext in hex format
    printf("Ciphertext: ");
    print_bytes_as_hex(ciphertext, ciphertext_length);
    printf("Ciphertext length: %lu\n", ciphertext_length);

    //**********************************************************************************************
    // Decrypt
    //**********************************************************************************************    

    rv = funcs->C_DecryptInit(session, &mech, aes_key);
    if (CKR_OK != rv) {
        printf("Decryption Init failed: %lu\n", rv);
        return rv;
    }

    // Determine how much memory is required to hold the decrypted text.
    CK_ULONG decrypted_ciphertext_length = 0;
    rv = funcs->C_Decrypt(session, ciphertext, ciphertext_length, NULL, &decrypted_ciphertext_length);
    if (CKR_OK != rv) {
        printf("Decryption failed: %lu\n", rv);
        goto done;
    }

    // Allocate memory for the decrypted ciphertext.
    decrypted_ciphertext = malloc(decrypted_ciphertext_length);
    if (NULL == decrypted_ciphertext) {
        rv = 1;
        printf("Could not allocate memory for decrypted ciphertext\n");
        goto done;
    }

    // Decrypt the ciphertext.
    rv = funcs->C_Decrypt(session, ciphertext, ciphertext_length, decrypted_ciphertext, &decrypted_ciphertext_length);
    if (CKR_OK != rv) {
        printf("Decryption failed: %lu\n", rv);
        goto done;
    }

    printf("Decrypted ciphertext: %.*s\n", (int)decrypted_ciphertext_length, decrypted_ciphertext);
    printf("Decrypted ciphertext length: %lu\n", decrypted_ciphertext_length);

done:
    if (NULL != decrypted_ciphertext) {
        free(decrypted_ciphertext);
    }

    if (NULL != ciphertext) {
        free(ciphertext);
    }
    return rv;
}

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;

    struct pkcs_arguments args = {};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return 1;
    }

    rv = pkcs11_initialize(args.library);
    if (CKR_OK != rv) {
        return 1;
    }
    rv = pkcs11_open_session(args.pin, &session);
    if (CKR_OK != rv) {
        return 1;
    }

    // CK_BYTE_PTR plaintext = "3ee0870404e76b4c8f37da936ec78f2a0583cf9a8bc62fe489887de1527e278b";
    CK_BYTE_PTR plaintext = argv[3];

    printf("\nEncrypt/Decrypt with AES CBC Pad\n");
    rv = aes_cbc_sample(session, plaintext);
    if (CKR_OK != rv) {
        return rv;
    }

    pkcs11_finalize_session(session);

    return 0;
}
