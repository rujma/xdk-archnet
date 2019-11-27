#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cwpack.h"
#include "cwpack_defines.h"
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <mbedtls/md.h>


#define LETTER_INPUT_SIZE 50


int create_aes_key(unsigned char* key)
{
    int ret;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    char *pers = "aes generate key";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if((ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers, strlen(pers))) != 0)
    {
        printf( " failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret );
        return 0;
    }

    if((ret = mbedtls_ctr_drbg_random( &ctr_drbg, key, 32)) != 0)
    {
        printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        return 0;

    }
    return 1;
}

int create_iv(unsigned char* iv)
{
    int ret;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    //char *pers = "iv generate key";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if(ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
    {
        printf( " failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret );
        return 0;
    }

    if((ret = mbedtls_ctr_drbg_random( &ctr_drbg, iv, 16)) != 0)
    {
        printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        return 0;

    }
    return 1;
}

int main (void)
{
    // Letter
    cw_pack_context pc_letter;
    cw_pack_context pc_letter_query;
    char letter_input[LETTER_INPUT_SIZE];
    char *letter_input_msgpack;
    mbedtls_aes_context aes;
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char letter_encrypted[LETTER_INPUT_SIZE];
    size_t iv_off;

    // Stamp
    cw_pack_context pc_stamp;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    static char stamp[128];
    unsigned char stamp_encrypted[128];  
    size_t olen = 0;
    char rsa_key[] = "-----BEGIN PUBLIC KEY-----\r\n"
                     "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwJNDlTBmRpWlQnMhpFLIOa0iK\r\n"
                     "OohCqW+b7xsPTjZn2Q8As3LCpYWepKyMkkl37IarI+H1BA+mLE6U4bwReX53clfC\r\n"
                     "b9qK7yjyoHVQJv6x1koys8rrwsp3e+l/BogZn0L+GO+wFzFosQx/hBtRqfamsHE9\r\n"
                     "E7lW4ZhnsbZMH6DMEQIDAQAB\r\n"
                     "-----END PUBLIC KEY-----\r\n\0";
    const char *pers = "mbedtls_pk_encrypt";

    // Auxiliary variables
    FILE * file_ptr;

    /* Randomly create the AES key and the IV */
    if(create_aes_key(key) == 0 || create_iv(iv) == 0)
        return -1;
    
    /* --------------------- STAMP --------------------- */
    /* Create the stamp */  
    cw_pack_context_init (&pc_stamp, stamp, 128, 0);
    cw_pack_array_size(&pc_stamp, 5);
    cw_pack_str(&pc_stamp, key, 32);
    cw_pack_str(&pc_stamp, iv, 16);
    cw_pack_str(&pc_stamp, "microservice1234", 15);
    cw_pack_str(&pc_stamp, "1", 1);
    cw_pack_str(&pc_stamp, "FILLING MESSAGE WITH TRASH", 26);
    int length_stamp = pc_stamp.current - pc_stamp.start;
    
    //file_ptr = fopen("test_pack.bin", "wb");
    //fwrite(stamp, sizeof(char), length_stamp, file_ptr);
    //fclose(file_ptr);
    
    printf("STAMP CREATION\n");

    /* Stamp encryption */
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) );
    mbedtls_pk_init( &pk );
    int ret;
    if( (ret = mbedtls_pk_parse_public_key( &pk, rsa_key, strlen(rsa_key) + 1 )) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parse_public_key returned -0x%04x\n", -ret );
        return -1;
    }

    fflush( stdout );
    if(  (ret = mbedtls_pk_encrypt( &pk, stamp, strlen(stamp) + 1, stamp_encrypted, &olen, sizeof(stamp_encrypted), mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf(" failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
        return -1;
    }
    printf("STAMP ENCRYPTION\n");

    /* --------------------- LETTER --------------------- */
    /* Create the letter */
    cw_pack_context_init (&pc_letter, letter_input, LETTER_INPUT_SIZE, 0);
    cw_pack_map_size (&pc_letter, 6);
    cw_pack_str (&pc_letter, "db", 2);
    cw_pack_str (&pc_letter, "test", 4);
    cw_pack_str (&pc_letter, "table", 5);
    cw_pack_str (&pc_letter, "data", 4);
    cw_pack_str (&pc_letter, "user", 4);
    cw_pack_str (&pc_letter, "admin", 5);
    cw_pack_str (&pc_letter, "pass", 4);
    cw_pack_str (&pc_letter, "admni", 5);
    cw_pack_str (&pc_letter, "op", 2);
    cw_pack_str (&pc_letter, "insert", 6);
    cw_pack_str (&pc_letter, "query", 5);
    int length = pc_letter.current - pc_letter.start;


    /* Trim the array with dynamic memory */
    letter_input_msgpack = (char *)malloc(length);
    memset(letter_input_msgpack, 0, length * sizeof(char));
    memcpy(letter_input_msgpack, letter_input, length);

    printf("LETTER CREATION\n");

    /* Letter Encryption */
    mbedtls_aes_setkey_enc(&aes, key, 256);  // Key is 32 Bytes - 32 * 8bits = 256
    mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, length, &iv_off, iv, letter_input_msgpack, letter_encrypted);
    
    /* Free memory */
    free(letter_input_msgpack);

    printf("LETTER ENCRYPTION\n");






    return 0;
}
