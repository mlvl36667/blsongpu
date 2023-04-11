#include "utils.h"
// Convert a number in RNS format using CRT
// x = [sum^{n}_{i=1} s_i[X_i*s^{-1}_i]_p_i] mod M
uint64_t  get_integer(uint64_t * rns,int dim,uint64_t * primes,uint64_t  m,uint64_t * svals,uint64_t * smvals){
 uint64_t  xsm1;
 uint64_t  ret = 0;
 for(int i=0;i < dim;i++){
  xsm1 = rns[i]*smvals[i] % primes[i];
  ret  = ret + svals[i] * xsm1;
 }
 return ret % m; 
}
void get_rns(uint64_t  number, uint64_t * primes, uint64_t * rns,int dim){
 for(int i=0;i < dim;i++){
  rns[i] = number % primes[i];
 }
}
uint64_t  modInverse(uint64_t  a, uint64_t  m)
{
    for (int x = 1; x < m; x++)
        if (((a % m) * (x % m)) % m == 1)
            return x;
}

void divrns(uint64_t * a,uint64_t * b,uint64_t * c, int dim, uint64_t * primes){
 for(int i=0;i < dim;i++){
  c[i] = a[i] / b[i];
  c[i] = c[i] % primes[i];
 }
}
void addrns(uint64_t * a,uint64_t * b,uint64_t * c, int dim, uint64_t * primes){
 for(int i=0;i < dim;i++){
  c[i] = a[i] + b[i];
  c[i] = c[i] % primes[i];
 }
}
void mulrns(uint64_t * a,uint64_t * b,uint64_t * c, int dim, uint64_t * primes){
 for(int i=0;i < dim;i++){
  c[i] = a[i] * b[i];
  c[i] = c[i] % primes[i];
 }
}

int get_random_number(){
    int randomvalue;
    FILE *fpointer;
    fpointer = fopen("/dev/urandom", "rb");
    if(fpointer == NULL){
     printf("fpointer == NULL in get_random_number \n");
    }
    fread(&randomvalue,sizeof(int),1,fpointer);  
    fclose(fpointer);
    return abs(randomvalue);
}
uint64_t power(uint64_t base, uint64_t exp) {
    if (exp == 0)
        return 1;
    else if (exp % 2)
        return (uint64_t)base * power(base, exp - 1);
    else {
        uint64_t temp = (uint64_t)power(base, exp / 2);
        return temp * temp;
    }
}
