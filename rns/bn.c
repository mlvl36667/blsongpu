#include <stdio.h>
#include <gmp.h>

int main()
{
    mpz_t a, b, c;
    mpz_t b1, b2, b3;
    mpz_t op1, op2;
    mpz_t s1, s2, s3;
    mpz_t sm1, sm2, sm3;

    mpz_init(a);    // inicializáljuk az 'a' változót
    mpz_init(b);    // inicializáljuk a 'b' változót
    mpz_init(c);    // inicializáljuk a 'c' változót
    mpz_init(b1);    // inicializáljuk a 'c' változót
    mpz_init(b2);    // inicializáljuk a 'c' változót
    mpz_init(b3);    // inicializáljuk a 'c' változót
    mpz_init(op1);    // inicializáljuk a 'c' változót
    mpz_init(op2);    // inicializáljuk a 'c' változót
    mpz_init(s1);    // inicializáljuk a 'c' változót
    mpz_init(s2);    // inicializáljuk a 'c' változót
    mpz_init(s3);    // inicializáljuk a 'c' változót

    mpz_init(sm1);    // inicializáljuk a 'c' változót
    mpz_init(sm2);    // inicializáljuk a 'c' változót
    mpz_init(sm3);    // inicializáljuk a 'c' változót

    // adjuk meg az 'a' és 'b' értékeit
    mpz_set_str(op1, "18446744073709551615", 10);
    mpz_set_str(op2, "1", 10);

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
    mpz_clear(op2);
    mpz_clear(op1);

    mpz_clear(s1);
    mpz_clear(s2);
    mpz_clear(s3);

    mpz_clear(sm1);
    mpz_clear(sm2);
    mpz_clear(sm3);

    return 0;
}
