#include <gmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>
#include <sys/time.h>
// Compile:  gcc -o bn bn.c -lgmp -lssl -lcrypto 
// The results is: 
// 19C38BACB92FE1AB DB60CB93953905D4 6074A7272E38D5B1 1BE58CE84F66949E 7C892A9D9BA26B3B 6E5762510852B323
// 0FF88E19FF154346 5E0BAFA097B616B8 0A81717E5A597AF5 71F023E723E3CB89 A9C63F913BEB0FD1 E33027CA5649D4F3
// 055ABA66857688CB F9027B0E501079C8 6F7A0A85671FA86F D053D9F741A56F0D F50B5BDF4AE80DA5 9B9E873BE7CFE6A0
// 1979ECA2D88265FB 96CF461427634369 7074995C4D3FA986 CEA781C98A77AAB4 F9F914F079C5C5D4 FCAC03952C4937EF
// 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000001
// 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000
// 
//  k: 
// 66CE306BA94292E45B3F16A92802BA54B1423F26BFEEFBDEDDDA0CC814EA75C33A0366D11B3E7EFBC7DACBE39903D67FE26425CB95BC40F179EAD0E2AB537E78
// 
//  printing in fp_prime_conv.... 
// 66CE306BA94292E45B3F16A92802BA54B1423F26BFEEFBDEDDDA0CC814EA75C33A0366D11B3E7EFBC7DACBE39903D67FE26425CB95BC40F179EAD0E2AB537E78
// 
//  printing in prime.... 
// 1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
// 
//  result of mod.... 
// 17D9CD3D0B18B44C0AC58332D8BF4AAFCC4C657AD2DD88FDABF1526D0D5D5825C71822F46E55190A50D01829F7C34C45
// result: 
// 17D9CD3D0B18B44C 0AC58332D8BF4AAF CC4C657AD2DD88FD ABF1526D0D5D5825 C71822F46E55190A 50D01829F7C34C45
// 
//  k: 
// E10CDC029D7B6584581F8F1422A4054E65F228AA30AC040381B785A5CFE16AFC9B35898186746314C232FF15CBDE635E2A2BF8EC73B0693EAE1355BEF869EA8A
// 
//  printing in fp_prime_conv.... 
// E10CDC029D7B6584581F8F1422A4054E65F228AA30AC040381B785A5CFE16AFC9B35898186746314C232FF15CBDE635E2A2BF8EC73B0693EAE1355BEF869EA8A
// 
//  printing in prime.... 
// 1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
// 
//  result of mod.... 
// 104E9B7244DCD23A4FE2F19933A78D4A6FCB776851BD59BE7CFD5A1052BC831919392A39F986ACBD5C41A6A5514B29F2
// result: 
// 104E9B7244DCD23A 4FE2F19933A78D4A 6FCB776851BD59BE 7CFD5A1052BC8319 19392A39F986ACBD 5C41A6A5514B29F2
// 
//  1. message: 
// 17D9CD3D0B18B44C 0AC58332D8BF4AAF CC4C657AD2DD88FD ABF1526D0D5D5825 C71822F46E55190A 50D01829F7C34C45
// 104E9B7244DCD23A 4FE2F19933A78D4A 6FCB776851BD59BE 7CFD5A1052BC8319 19392A39F986ACBD 5C41A6A5514B29F2
// 17D9CD3D0B18B44C 0AC58332D8BF4AAF CC4C657AD2DD88FD ABF1526D0D5D5825 C71822F46E55190A 50D01829F7C34C45
// 104E9B7244DCD23A 4FE2F19933A78D4A 6FCB776851BD59BE 7CFD5A1052BC8319 19392A39F986ACBD 5C41A6A5514B29F2
// 0EF1CECBCD175EBC A369D4BA5E2E8A2F 0DF256EB7F7A1006 07581C37104AA96C BADCE5F7CCEE841B 99CFDA5E26D46CA5
// 0E63F599550520E6 C3A75C5507FC4ADF 95C011FAB2DFA937 4FBC9EA6DA15512D 6766777A074FC8D8 F68538D1E99A4026
// 0EF1CECBCD175EBC A369D4BA5E2E8A2F 0DF256EB7F7A1006 07581C37104AA96C BADCE5F7CCEE841B 99CFDA5E26D46CA5
// 0E63F599550520E6 C3A75C5507FC4ADF 95C011FAB2DFA937 4FBC9EA6DA15512D 6766777A074FC8D8 F68538D1E99A4026
// 0EF1CECBCD175EBC A369D4BA5E2E8A2F 0DF256EB7F7A1006 07581C37104AA96C BADCE5F7CCEE841B 99CFDA5E26D46CA5
// 0E63F599550520E6 C3A75C5507FC4ADF 95C011FAB2DFA937 4FBC9EA6DA15512D 6766777A074FC8D8 F68538D1E99A4026
// 0EF1CECBCD175EBC A369D4BA5E2E8A2F 0DF256EB7F7A1006 07581C37104AA96C BADCE5F7CCEE841B 99CFDA5E26D46CA5
// 0E63F599550520E6 C3A75C5507FC4ADF 95C011FAB2DFA937 4FBC9EA6DA15512D 6766777A074FC8D8 F68538D1E99A4026
// 0EF1CECBCD175EBC A369D4BA5E2E8A2F 0DF256EB7F7A1006 07581C37104AA96C BADCE5F7CCEE841B 99CFDA5E26D46CA5
// 0E63F599550520E6 C3A75C5507FC4ADF 95C011FAB2DFA937 4FBC9EA6DA15512D 6766777A074FC8D8 F68538D1E99A4026
// 
//  k: 
// 79B345FCB6BA31434774A5A506F53E0A32F4E9BC1B73CFB6D7720A61BA00962E9FD3CF91746801920C63E458DFB9FC17ABAC01801BEE343ADFA63C0938BB0478
// 
//  printing in fp_prime_conv.... 
// 79B345FCB6BA31434774A5A506F53E0A32F4E9BC1B73CFB6D7720A61BA00962E9FD3CF91746801920C63E458DFB9FC17ABAC01801BEE343ADFA63C0938BB0478
// 
//  printing in prime.... 
// 1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
// 
//  result of mod.... 
// 310022C690DEBC74AADE88A7725096800314424FB7DC46D174262E9E8FEE80C7E3746894BCEDDCB2C63F2ABC70C0087
// result: 
// 0310022C690DEBC7 4AADE88A77250968 00314424FB7DC46D 174262E9E8FEE80C 7E3746894BCEDDCB 2C63F2ABC70C0087
// 
//  k: 
// D5EC78C1A4ACF30FB791DD5B6CE1FCA772C04D33FCB5FB78F8C36C873436304346AC1D586448C4590DAB5B9AB4EEECB942E6A1C073640D3605EA1464CFBA0DC7
// 
//  printing in fp_prime_conv.... 
// D5EC78C1A4ACF30FB791DD5B6CE1FCA772C04D33FCB5FB78F8C36C873436304346AC1D586448C4590DAB5B9AB4EEECB942E6A1C073640D3605EA1464CFBA0DC7
// 
//  printing in prime.... 
// 1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
// 
//  result of mod.... 
// C11F9BC07FF9896797B89947DB5610DB34AF451B140F453A8ABD35821F41756596188D45AEB9BE412FA7183963F03F2
// result: 
// 0C11F9BC07FF9896 797B89947DB5610D B34AF451B140F453 A8ABD35821F41756 596188D45AEB9BE4 12FA7183963F03F2
// 
//  2. message: 
// 0310022C690DEBC7 4AADE88A77250968 00314424FB7DC46D 174262E9E8FEE80C 7E3746894BCEDDCB 2C63F2ABC70C0087
// 0C11F9BC07FF9896 797B89947DB5610D B34AF451B140F453 A8ABD35821F41756 596188D45AEB9BE4 12FA7183963F03F2
// 0310022C690DEBC7 4AADE88A77250968 00314424FB7DC46D 174262E9E8FEE80C 7E3746894BCEDDCB 2C63F2ABC70C0087
// 0C11F9BC07FF9896 797B89947DB5610D B34AF451B140F453 A8ABD35821F41756 596188D45AEB9BE4 12FA7183963F03F2
// 152CC78DE36EB794 9EF1BB8ADA81578B 5F13D9F269BD8024 E3AD0BBCE48A9766 9A8FD6CE9AE2351E 3B14ABB99F0D91A4
// 0C7A1C10848E8C8F CFDD9F84C0BB53A0 8B071F303A3AAD05 4ACF8648075FB8D5 B21C5662E3DC7ABA 093ED39930F0A720
// 152CC78DE36EB794 9EF1BB8ADA81578B 5F13D9F269BD8024 E3AD0BBCE48A9766 9A8FD6CE9AE2351E 3B14ABB99F0D91A4
// 0C7A1C10848E8C8F CFDD9F84C0BB53A0 8B071F303A3AAD05 4ACF8648075FB8D5 B21C5662E3DC7ABA 093ED39930F0A720
// 152CC78DE36EB794 9EF1BB8ADA81578B 5F13D9F269BD8024 E3AD0BBCE48A9766 9A8FD6CE9AE2351E 3B14ABB99F0D91A4
// 0C7A1C10848E8C8F CFDD9F84C0BB53A0 8B071F303A3AAD05 4ACF8648075FB8D5 B21C5662E3DC7ABA 093ED39930F0A720
// 152CC78DE36EB794 9EF1BB8ADA81578B 5F13D9F269BD8024 E3AD0BBCE48A9766 9A8FD6CE9AE2351E 3B14ABB99F0D91A4
// 0C7A1C10848E8C8F CFDD9F84C0BB53A0 8B071F303A3AAD05 4ACF8648075FB8D5 B21C5662E3DC7ABA 093ED39930F0A720
// 152CC78DE36EB794 9EF1BB8ADA81578B 5F13D9F269BD8024 E3AD0BBCE48A9766 9A8FD6CE9AE2351E 3B14ABB99F0D91A4
// 0C7A1C10848E8C8F CFDD9F84C0BB53A0 8B071F303A3AAD05 4ACF8648075FB8D5 B21C5662E3DC7ABA 093ED39930F0A720


static __inline__ unsigned long long rdtsc(void)
{
    unsigned long long int x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
    return x;
}
void rns_sum(mpz_t c, mpz_t a, mpz_t b, int exp){
// calculate c = a + b using rns representations
 mpz_t b1, b2, b3;
 mpz_t s1, s2, s3;
 mpz_t sm1, sm2, sm3;
 mpz_t res1, res2, res3;
 mpz_t res11, res22, res33;
 mpz_t ap1, ap2, ap3;
 mpz_t bp1, bp2, bp3;
 mpz_t one, two;

 unsigned long long start, end;


 mpz_init(one);    
 mpz_init(two);    
 mpz_set_str(one, "1", 16);
 mpz_set_str(two, "2", 16);

 mpz_init(ap1);    
 mpz_init(ap2);    
 mpz_init(ap3);    

 mpz_init(bp1);    
 mpz_init(bp2);    
 mpz_init(bp3);    

 mpz_init(b1);    
 mpz_init(b2);    
 mpz_init(b3);    

 mpz_init(s1);    
 mpz_init(s2);    
 mpz_init(s3);    

 mpz_init(sm1);    
 mpz_init(sm2);    
 mpz_init(sm3);    

 mpz_init(res1);    
 mpz_init(res2);    
 mpz_init(res3);    

 mpz_init(res11);    
 mpz_init(res22);    
 mpz_init(res33);    

 printf("op1: \n");
 mpz_out_str(stdout,16,a);
 printf(" \n");
 printf("op2: \n");
 mpz_out_str(stdout,16,b);
 printf(" \n");
// New Multi-Moduli Residue and Quadratic Residue Systems for Large Dynamic Ranges (Mohammad Abdallah and Alexander Skavantzos)
// https://ieeexplore.ieee.org/document/540842
// The most popular such sets are the 3-moduli set (2^{n}-1, 2^{n}, 2^{n}+1) and the 4-moduli set (2^{n-1}-1, 2^{n}-1, 2^{n+1}-1, 2^{n+1}) for even n .
 mpz_pow_ui(b2,two,exp);
 mpz_sub(b1,b2,one);
 mpz_add(b3,b2,one);

 printf("p1: \n");
 mpz_out_str(stdout,10,b1);
 printf(" \n");
 printf("p2: \n");
 mpz_out_str(stdout,10,b2);
 printf(" \n");
 printf("p3: \n");
 mpz_out_str(stdout,10,b3);
 printf(" \n");

// mpz_set_str(b1, "4194303", 10);
// mpz_set_str(b2, "4194304", 10);
// mpz_set_str(b3, "4194305", 10);

 mpz_mul(s1, b2, b3);
 mpz_mul(s2, b1, b3);
 mpz_mul(s3, b1, b2);
//    printf(" \n");
//    mpz_out_str(stdout,10,s1);
//    printf(" \n");
//    mpz_out_str(stdout,10,s2);
//    printf(" \n");
//    mpz_out_str(stdout,10,s3);
 mpz_invert(sm1, s1, b1);
 mpz_invert(sm2, s2, b2);
 mpz_invert(sm3, s3, b3);

 start = rdtsc();
 mpz_mod(ap1,a,b1);
 mpz_mod(ap2,a,b2);
 mpz_mod(ap3,a,b3);

 mpz_mod(bp1,b,b1);
 mpz_mod(bp2,b,b2);
 mpz_mod(bp3,b,b3);

 mpz_add(res1,ap1,bp1);
 mpz_mod(res11,res1,b1);

 mpz_add(res2,ap2,bp2);
 mpz_mod(res22,res2,b2);

 mpz_add(res3,ap3,bp3);
 mpz_mod(res33,res3,b3);

// restore
 mpz_mul(res1,res11,sm1);
 mpz_mod(res11,res1,b1);
 mpz_mul(res2,res22,sm2);
 mpz_mod(res22,res2,b2);
 mpz_mul(res3,res33,sm3);
 mpz_mod(res33,res3,b3);

 mpz_mul(res1,res11,s1);
// mpz_mod(res11,res1,b1);
 mpz_mul(res2,res22,s2);
// mpz_mod(res22,res2,b2);
 mpz_mul(res3,res33,s3);
// mpz_mod(res33,res3,b3);

 mpz_add(res11,res1,res2);
 mpz_add(res22,res11,res3);

 mpz_mul(res1,b1,b2);
 mpz_mul(res3,res1,b3);

 mpz_mod(res1,res22,res3);

 end = rdtsc();
 printf("Elapsed clock cycles: %llu\n", end - start);

 printf("res using rns: \n");
 mpz_out_str(stdout,16,res1);
 printf(" \n");

 printf("p1*p2*..pn : \n");
 mpz_out_str(stdout,16,res3);
 printf(" \n");


 start = rdtsc();
 mpz_add(c,a,b);
 end = rdtsc();
 printf("Elapsed clock cycles: %llu\n", end - start);



 printf("res using MPZ: \n");
 mpz_out_str(stdout,16,c);
 printf(" \n");

 return;
}
int main(int argc, char *argv[])
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
 mpz_t t00;

 mpz_init(t00);    

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

// mpz_set_str(t_0, "3ffffffffffbffffe", 16);
// mpz_set_str(t_0, "3ffffffffffc00000", 16);
// mpz_set_str(t_1, "1", 16);

// mpz_sub(op1,t_0,t_1);
// printf("sub: \n");
// mpz_out_str(stdout,16,op1);
// printf(" \n");

 mpz_set_str(t_0, "79B345FCB6BA31434774A5A506F53E0A32F4E9BC1B73CFB6D7720A61BA00962E9FD3CF91746801920C63E458DFB9FC17ABAC01801BEE343ADFA63C0938BB0478", 16);
 mpz_set_str(t_1, "D5EC78C1A4ACF30FB791DD5B6CE1FCA772C04D33FCB5FB78F8C36C873436304346AC1D586448C4590DAB5B9AB4EEECB942E6A1C073640D3605EA1464CFBA0DC7", 16);

 mpz_mod(t0p,t_0,prime);
 mpz_mod(t1p,t_1,prime);

// printf(" \n");
// mpz_out_str(stdout,16,t_0);
// printf(" \n");
// mpz_out_str(stdout,16,t_1);
// printf(" \n");
//
// printf(" \n");
// mpz_out_str(stdout,16,t0p);
// printf(" \n");
// mpz_out_str(stdout,16,t1p);
// printf(" \n");
 int exp = atoi(argv[1]);
 rns_sum(t00,t0p,t1p,exp);

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
