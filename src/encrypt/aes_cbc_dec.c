/*
 * ofer.rivlin@cyberark.com
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "/home/ubuntu/pkcs11/aws-cloudhsm-pkcs11-examples/include/pkcs11/v2.40/cryptoki.h"
#include "aes.h"

CK_BYTE_PTR hexstr_to_char(const char* hexstr) // https://gist.github.com/xsleonard/7341172
{
    size_t len = strlen(hexstr);
    if (len % 2 != 0)
        return NULL;
    size_t final_len = len / 2;
    CK_BYTE_PTR chrs = (CK_BYTE_PTR)malloc((final_len+1) * sizeof(*chrs));
    for (size_t i=0, j=0; j<final_len; i+=2, j++){
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
        printf("%d",chrs[j]);
    }
    chrs[final_len] = '\0';
    size_t size = sizeof(chrs) / sizeof(chrs[0]); 
    printf("chrs length: %lu\n", size);
    return chrs;
}

/**
 * Encrypt and decrypt the encryption-service key using AES CBC.
 * @param session Active PKCS#11 session
 */
CK_RV aes_cbc_sample(CK_SESSION_HANDLE session, CK_BYTE_PTR ciphertext, CK_ULONG ciphertext_length) {
    CK_RV rv;

    CK_OBJECT_HANDLE aes_key = 6;

    // Prepare the mechanism 
    // The IV is hardcoded to all 0x01 bytes for this example.
    CK_BYTE iv[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    CK_MECHANISM mech = {CKM_AES_CBC_PAD, iv, 16};

    //**********************************************************************************************
    // Decrypt
    //**********************************************************************************************    

    CK_BYTE_PTR decrypted_ciphertext = NULL;

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

    // CK_BYTE_PTR ciphertext = "8FBA9338D29CA726239A57870FA3DF5887A11187CE35738106AF12DF7B36E4E7D9DDB5EC2AD50085EB6E1C25A80830611D5444F2A9B48566C1380052E7E7AE7C0651B604B2979F51EA29DAE38AB83810";
    CK_BYTE_PTR hex_ciphertext = argv[3];
    CK_ULONG hex_ciphertext_length = strlen(hex_ciphertext);
    CK_ULONG ciphertext_length = hex_ciphertext_length / 2;
    printf("Hex-Ciphertext: %s\n", hex_ciphertext);
    printf("Hex-Ciphertext length: %lu\n", hex_ciphertext_length);

    CK_BYTE_PTR ciphertext = hexstr_to_char(hex_ciphertext);

    if (NULL != ciphertext) {
        printf("\nEncrypt/Decrypt with AES CBC Pad\n");
        rv = aes_cbc_sample(session, ciphertext, ciphertext_length);
        if (CKR_OK != rv) {
            return rv;
        }
    }

    pkcs11_finalize_session(session);

    return 0;
}
