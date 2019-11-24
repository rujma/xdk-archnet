#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

int main()
{

  int ret=0;

  // random data generator
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init( &entropy );

  // randomness with seed
  mbedtls_ctr_drbg_context ctr_drbg;
  char *personalization = "My RSA demo";
  mbedtls_ctr_drbg_init( &ctr_drbg );

  ret = mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy,
                     (const unsigned char *) personalization,
                     strlen( personalization ) );
  if( ret != 0 )
  {
        // ERROR HANDLING CODE FOR YOUR APP
  }
  mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg, 
                                              MBEDTLS_CTR_DRBG_PR_ON );
////////////////////////////////////////////////////////////////////////  
  mbedtls_pk_context pk;
  mbedtls_pk_init( &pk );
  unsigned char to_encrypt[]="Ford_Mustang";
  unsigned char to_decrypt[MBEDTLS_MPI_MAX_SIZE];
  const unsigned char pub_key[]=
"-----BEGIN PUBLIC KEY-----\r\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8odCEA58lHtFdC6WPyhK\r\n"
"JCxJ1TdC9ivvwWrrzWOVK7NHzOLxw7l6HnwfQTV5EzN5KoWxy1KB/oSIJHX2dhfq\r\n"
"v3TF+5SixZfueYCok/6+Bm6p8UC2ZMU32QhlVcctmp3lL7lqB5mKQ4pzFi9gU7/e\r\n"
"a5GYYwYlcfUZTa57HDCz0xs3sWOKLa6FQlb3oZanATuzCDy+xFD1G1jXdhqo16zR\r\n"
"rITSoRjj0TIQHVYYSN5QyrDn76wmc9uPyxCDdbIjcUMdkKWpBwr+qjHDWoP/B0pG\r\n"
"RfXI2lyc4FgQwoMgefQH83Y0uuqdaCmlbRS1oBj1QmQDB2ZNieLR2Lo7zJnZudq/\r\n"
"jQIDAQAB\r\n"
"-----END PUBLIC KEY-----\r\n";


  const unsigned char prv_pwd[]="password";
  const unsigned char prv_key[]=
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"Proc-Type: 4,ENCRYPTED\r\n"
"DEK-Info: DES-EDE3-CBC,3EC69988AA24B880\r\n"
"\r\n"
"ICT5eSqa9K0qUrqF3XsX3iikGqgXESl3mkJDi0nBZR5wPfxhu8V7VBB54DOVmXMt\r\n"
"fk3lxYQdBpzog4YqCavpKOFhqqehNHEoFdaP71M+743SzCNXmXvxwmuMzgFdyOzb\r\n"
"4RDFyim7bQP/8jNpnOaUZ0N2Vm9p1tKeMaLGwA7U8LTpRUHydkaoNL7vxnBykuh/\r\n"
"9zt52td/Ho5tGmroVGT9+75Oz7IKUWRdX2Ab9A98iysRTJOxVFl5VUZWmBMeFhxR\r\n"
"668ewADNA4t7McoePV24xK6ocF6oztDNGTYyRZ0FnwEZF4wYLDKlP1n5mGqXiuuD\r\n"
"4D/0Vco3p8g+R4yjVzzNnbBWCFJSs6ObMXXkb2fOytlxtDkkmfbCawGKQt8ibQkR\r\n"
"MxUB3AW34EVnjJ8fcXuDwqOKnVmvhJxN+uQHRsazqyHS9yQKCZgoZfMLWug6d1mw\r\n"
"hosCZAIZMcLr1gXFu52Ti5T6lEMc8saZZmymy6gCoFtZx1nkxzsFao9WpzrAEvua\r\n"
"SyJt2/3pkIu+B/abuM+vEEs1zjs+eJvXiEua6AqoBYcev3H1WDTuQw+e+XSRm+dc\r\n"
"jM7pBy+xs6e93jfiuUIiGDIrwETYhpFjVw442WkRYMcv0cIAOpiVeWvHQphJCyEL\r\n"
"xuol725hHwh4DBgfLbe1AdlbTcf44W0woAAA2CxWhONRXOOfQYjEdflEULT2ukDn\r\n"
"V5QRBac2QWenSndBB7CI8eufhwQonWXvnT+nprX9U9/QDu7XIfCD/9wsBnYJNwq8\r\n"
"XtDEMWMkLO23BZuwiT8ZhqRK97g4pvU7Q++fwX3oPZ3wpJgcAYOgRO2nVaJC0NfL\r\n"
"QuyZZwpPJIOsdF/DVqWczw45nqtW0MSjYCVf9jW5f5oWKD2vWsf0zr5m2NgPf4bW\r\n"
"oOeulZW6O6WN3vMKCBDZlyOz0OKmMjxL32Q3LRpDOuULjAi1iYlMrJTPcID/pUpe\r\n"
"r1f3Saqm6MU9DPJELNEvABliCmwYQIJQBIKPciiqAogAxcf84/uC9+MSLldh/ehZ\r\n"
"e3jCu0uFA9ft99RUdzC/HGcT+NJ+ONenkxHOhzyW+qG4UHnbWdz8c2sNLdcyMnic\r\n"
"Iy3MKb+EfsaVh+5DZASYsrxVOU8SCPN+z6mgBfDvGWO0FTmLoxY9xQI9wjPMzMZJ\r\n"
"p7HHS662/lRPl+Ga5evIU4mt5UcL8KonHnDew5Tltd6JND28gwsmMX+JhOPNcuhU\r\n"
"sIVC0PEChQqC5zomF2Yb8vxlmgrZX4tpdrGVNjDcslBcvlerRYpYCc4kYC/cgam6\r\n"
"uzPpuNhnFbhjrXb2slsPKx8inXMKXbMzH0eZ3Pu2aO6zy7YUB0myldi8G4mWe5en\r\n"
"szGRpii6rbqVNXxTmUPKKtdmclvICPz6N1m8qW51b5OU0jaOInWCiKvNGS0Ya1t+\r\n"
"3K9c0dM0UnBTiizuPAqYCAiaaq4Z7/7/z5axvOYS00rLCeN5JZixOdEtm5PzUcaQ\r\n"
"hHC7zRri+blVXKef8ZaMwXQQfuNTPeOMARolipP0IXfonGNG1YUr9uc+tl60IBqt\r\n"
"PuJMYUqFTJBXCb5+HmvyD+0UAoO2hXSi0KPjQuXWNHBB02JQE14wAw==\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

  if( ( ret = mbedtls_pk_parse_public_key( &pk, pub_key, sizeof(pub_key) ) ) != 0 )
  {
    printf( " failed\n ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret );
    return -1;
  }

  unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
  size_t olen = 0;

  printf( "\nGenerating the encrypted value\n" );
  fflush( stdout );

  if( ( ret = mbedtls_pk_encrypt( &pk, to_encrypt, sizeof(to_encrypt),
                                  buf, &olen, sizeof(buf),
                                  mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
  {
    printf( " failed\n ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
    return -1;
  }

  for(int idx=0; idx<strlen(buf); printf("%02x", buf[idx++]));
  printf ("\n");

  mbedtls_pk_context pk1;

  mbedtls_pk_init(&pk1);
  if( ( ret = mbedtls_pk_parse_key( &pk1, prv_key, sizeof(prv_key), prv_pwd, strlen(prv_pwd) ) ) != 0 )
  {
    printf( " failed\n ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret );
    return -1;
  }

  unsigned char result[MBEDTLS_MPI_MAX_SIZE];
  olen = 0;

  printf( "\nGenerating the decrypted value" );
  fflush( stdout );

  if( ( ret = mbedtls_pk_decrypt( &pk1, buf, strlen(buf), result, &olen, sizeof(result),
                                    mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
  {
        printf( " failed\n! mbedtls_pk_decrypt returned -0x%04x\n", -ret );
        return -1;
  }
  else
  {

    fflush( stdout );
    printf("\n\n%s----------------\n\n", result);
  }

  return 0;
}
