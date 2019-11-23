#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cwpack.h"
#include "cwpack_defines.h"
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>


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
    
    cw_pack_context pc;
    cw_pack_context pc_array;
    char input[40];
    char *input_msgpack;

    FILE * file_ptr;


    // Stamp
    static char stamp[128];

   // Encrypt layer
    mbedtls_aes_context aes;
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char output[40];
    size_t iv_off;

    cw_pack_context_init (&pc, input, 40, 0);
    cw_pack_context_init (&pc_array, stamp, 128, 0);
    cw_pack_map_size (&pc, 3);
    cw_pack_array_size(&pc_array, 4);
    cw_pack_str (&pc, "db", 2);
    cw_pack_str (&pc, "test", 4);
    cw_pack_str (&pc, "table", 5);
    cw_pack_str (&pc, "data", 4);
    cw_pack_str (&pc, "user", 4);
    cw_pack_str (&pc, "admin", 5);


    cw_pack_str(&pc_array, "123", 3);
    cw_pack_str(&pc_array, "123", 3);
    cw_pack_str(&pc_array, "123", 3);
    cw_pack_str(&pc_array, "123", 3);

    int length1 = pc_array.current - pc_array.start;

    printf("%ld\n", sizeof(stamp));
    file_ptr = fopen("test_pack.bin", "wb");
    fwrite(stamp, sizeof(char),  length1,file_ptr);
    fclose(file_ptr);
    

    int length = pc.current - pc.start;
    printf("%ld\n", length1);

    /* Trim the array with dynamic memory */
    input_msgpack = (char *)malloc(length);
    memset(input_msgpack, 0, length * sizeof(char));
    memcpy(input_msgpack, input, strlen(input));

    /* Randomly create the AES key and the IV */
    if(create_aes_key(key) == 0 || create_iv(iv) == 0)
        return -1;
    
    // As the keys are create, we create the stamp
    strcpy(stamp, key);
    strcat(stamp, iv);
    strcat(stamp, "microservice");
    strcat(stamp, "1");

    /* Encryption */
    mbedtls_aes_setkey_enc(&aes, key, 256);  // Key is 32 Bytes - 32 * 8bits = 256
    mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, length, &iv_off, iv, input_msgpack, output);

    //printf("KEY:%s\nIV:%s\nINPUT:%s\nOUTPUT:%s\n", key, iv, input_msgpack, output);

    /* Free memory */
    free(input_msgpack);
    return 0;
}
