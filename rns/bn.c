#include <gmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
// Compile:  gcc -o bn bn.c -lgmp -lssl -lcrypto 

int main()
{
    mpz_t a, b, c;
    mpz_t b1, b2, b3;
    mpz_t op1, prime;
    mpz_t s1, s2, s3;
    mpz_t sm1, sm2, sm3;

    mpz_init(a);    // inicializáljuk az 'a' változót
    mpz_init(b);    // inicializáljuk a 'b' változót
    mpz_init(c);    // inicializáljuk a 'c' változót
    mpz_init(b1);    // inicializáljuk a 'c' változót
    mpz_init(b2);    // inicializáljuk a 'c' változót
    mpz_init(b3);    // inicializáljuk a 'c' változót
    mpz_init(op1);    // inicializáljuk a 'c' változót
    mpz_init(prime);    // inicializáljuk a 'c' változót
    mpz_init(s1);    // inicializáljuk a 'c' változót
    mpz_init(s2);    // inicializáljuk a 'c' változót
    mpz_init(s3);    // inicializáljuk a 'c' változót

    mpz_init(sm1);    // inicializáljuk a 'c' változót
    mpz_init(sm2);    // inicializáljuk a 'c' változót
    mpz_init(sm3);    // inicializáljuk a 'c' változót

    // adjuk meg az 'a' és 'b' értékeit
    mpz_set_str(op1, "18446744073709551615", 10);
    mpz_set_str(prime, "1", 10);

    mpz_set_str(b1, "4194303", 10);
    mpz_set_str(b2, "4194304", 10);
    mpz_set_str(b3, "4194305", 10);
    printf(" \n");
    mpz_out_str(stdout,10,b1);
    printf(" \n");
    mpz_out_str(stdout,10,b2);
    printf(" \n");
    mpz_out_str(stdout,10,b3);

    mpz_mul(c, b1, b2);
    mpz_mul(a, c, b3);

    mpz_mul(s1, b2, b3);
    mpz_mul(s2, b1, b3);
    mpz_mul(s3, b1, b2);

    printf(" \n");
    mpz_out_str(stdout,10,s1);
    printf(" \n");
    mpz_out_str(stdout,10,s2);
    printf(" \n");
    mpz_out_str(stdout,10,s3);

    int success = mpz_invert(sm1, s1, b1);

    if (success == 1) {
      printf(" \n");
      printf("\n sm1: \n");
      mpz_out_str(stdout,10,sm1);
    } else {
      printf(" Not coprime 1.  \n");
      mpz_out_str(stdout,10,s1);
      printf(" \n");
      mpz_out_str(stdout,10,b1);
      mpz_gcd(sm1,s1,b1);
      printf(" \n");
      mpz_out_str(stdout,10,sm1);
    }
    success = mpz_invert(sm2, s2, b2);
    if (success == 1) {
      printf("\n sm2: \n");
      mpz_out_str(stdout,10,sm2);
    } else {
      printf(" Not coprime 2.  \n");
    }
    success = mpz_invert(sm3, s3, b3);
    if (success == 1) {
      printf("\n sm3: \n");
      mpz_out_str(stdout,10,sm3);
    } else {
      printf(" Not coprime 3.  \n");
    }

    // kiíratjuk az eredményt
    printf(" \n");
    mpz_out_str(stdout,16,b1);
    printf(" \n");
    mpz_out_str(stdout,16,b2);
    printf(" \n");
    mpz_out_str(stdout,16,a);
    printf(" \n");
    mpz_out_str(stdout,16,b);

    // felszabadítjuk a memóriát
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(c);
    mpz_clear(b1);
    mpz_clear(b2);
    mpz_clear(b3);
    mpz_clear(op1);

    mpz_clear(s1);
    mpz_clear(s2);
    mpz_clear(s3);

    mpz_clear(sm1);
    mpz_clear(sm2);
    mpz_clear(sm3);

    mpz_set_str(prime, "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
    // ellenőrizzük a számot, 25 iterációval
    printf(" \n");
    mpz_out_str(stdout,16,prime);
    printf(" \n");
    int result = mpz_probab_prime_p(prime, 300);

    if (result == 0)
    {
        printf("A szam nem prim.\n");
    }
    else if (result == 1)
    {
        printf("A szam nagy valoszinuseggel prim.\n");
    }
    else
    {
        printf("A szam biztosan prim.\n");
    }

    mpz_init(prime);    // inicializáljuk a 'c' változót
    unsigned char hash[SHA256_DIGEST_LENGTH];
    const char hash2[SHA256_DIGEST_LENGTH];
    char data[] = "example data";
    char *data2;

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, strlen(data));
    SHA256_Final(hash, &sha256);

    data2 = (char*)malloc(((SHA256_DIGEST_LENGTH-1)*2+1+1)*sizeof(char));
    printf(" Hash: \n");

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(data2 + i * 2, "%02x", hash[i]);
    }
    data2[(SHA256_DIGEST_LENGTH)*2+1] = '\0';
    printf(" \n");
    printf(" Data2: \n");
    printf("%s", data2);

    mpz_set_str(prime, data2, 16);

    printf(" \n");
    mpz_out_str(stdout,2,prime);
    printf(" \n");
    mpz_out_str(stdout,16,prime);
    printf(" \n");
    mpz_out_str(stdout,10,prime);
    printf(" \n");
// -----------------------  //
// Map 't' to the curve based on ' Fast and simple constant-time hashing to the BLS12-381 elliptic curve ' https://tches.iacr.org/index.php/TCHES/article/view/8348
// #define B12_P381_MAPU0 "-2"
// #define B12_P381_MAPU1 "-1"
//  memcpy(str, B12_P381_MAPU0, sizeof(B12_P381_MAPU0));
//  fp_read_str(shared_map_u[0], str, 2, 16);
//  memcpy(str, B12_P381_MAPU1, sizeof(B12_P381_MAPU1));
//  fp_read_str(shared_map_u[1], str, 2, 16);
// #define B12_P381_ISO_A0 "0"
// #define B12_P381_ISO_A1 "F0"
// #define B12_P381_ISO_B0 "3F4"
// #define B12_P381_ISO_B1 "3F4"

 printf(" Now constructing t...\n");
 mpz_set_str(prime, "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);

 mpz_t a0, a1;
 mpz_t b0, am1;
 mpz_t u0, u1;
 mpz_t t0;
 mpz_t t_0, t_1;
 mpz_t t0p, t1p;

 mpz_init(a0);    
 mpz_init(a1);    
 mpz_init(b0);    
 mpz_init(b1);    
 mpz_init(u0);    
 mpz_init(u1);    
 mpz_init(t0);    
 mpz_init(t0p);    
 mpz_init(t1p);    

 mpz_init(t_0);    
 mpz_init(t_1);    

 mpz_set_str(a0, "0", 16);
 mpz_set_str(a1, "F0", 16);
 mpz_set_str(b0, "3F4", 16);
 mpz_set_str(b1, "3F4", 16);

 mpz_set_str(u0, "1", 16);
 mpz_set_str(u1, "2", 16);

 mpz_set_str(t_0, "79B345FCB6BA31434774A5A506F53E0A32F4E9BC1B73CFB6D7720A61BA00962E9FD3CF91746801920C63E458DFB9FC17ABAC01801BEE343ADFA63C0938BB0478", 16);
 mpz_set_str(t_1, "D5EC78C1A4ACF30FB791DD5B6CE1FCA772C04D33FCB5FB78F8C36C873436304346AC1D586448C4590DAB5B9AB4EEECB942E6A1C073640D3605EA1464CFBA0DC7", 16);

 mpz_mod(t0p,t_0,prime);
 mpz_mod(t1p,t_1,prime);

 printf(" \n");
 mpz_out_str(stdout,16,t_0);
 printf(" \n");
 mpz_out_str(stdout,16,t_1);
 printf(" \n");

 printf(" \n");
 mpz_out_str(stdout,16,t0p);
 printf(" \n");
 mpz_out_str(stdout,16,t1p);
 printf(" \n");

//  mpz_neg(u0,u0);
//  mpz_neg(u1,u1);
// 
//  /* c1 = -a */
//  mpz_neg(a1,a1);
// 
//  /* c1 = -1 / a */
// // itt a prim testben kell multiplikativ inverzt keresni? meg kell nezni az implementacioban 
//  mpz_div(am1,a1,prime);
//  /* c1 = -b / a */
//  mpz_mul(t0,b0,am1);
 /* t0 = u * t^2 */
 /* t1 = u^2 * t^4 */
 /* t2 = u^2 * t^4 + u * t^2 */ 
 /* t3 = -u */ 
 /* t2 = -1/u or 1/(u^2 * t^4 + u*t^2) */
 /* t3 = 1 + t2 */  
 /* only add 1 if t2 != -1/u */ 
 /* -B / A * (1 + 1 / (u^2 * t^4 + u * t^2)) */
 /* x^2 */ 
 /* x^2 + a */ 
 /* x^3 + a x */ 
 /* x^3 + a x + b */ 
 /* t2 = u * t^2 * x1 */
 /* t1 = u^3 * t^6 */  
 /* t5 = g(t2) = u^3 * t^6 * g(p->x) */
 /* second sqr */
 /* t2 = u * t^2 * x1 */
 /* t1 = t^3 */
 /* t0 = u^3 */
 /* t3 = sqrt(u^3) */
 /* t0 = u * t^2 */
 /* t3 = -u */  
 /* t5 = g(t2) = u^3 * t^6 * g(p->x) */ 
    mpz_clear(prime);

    mpz_clear(t_0);
    mpz_clear(t_1);

    free(data2);

    return 0;
}
