#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "utils.h"
#include <time.h>
#include <inttypes.h>

int main(){

 u_int64_t primes[10];
 u_int64_t svals[10];
 u_int64_t smvals[10];
 u_int64_t dim;
 u_int64_t m;
 u_int64_t k;

 dim = 3;
 k = 11;
 primes[0] = power(2,k)-1;
 primes[1] = power(2,k);
 primes[2] = power(2,k)+1;
 m = 1;
 for(int i=0;i < dim;i++){
 printf(" %" PRId64 " ",primes[i]);
  m = m*primes[i];
 }
 printf("m: %" PRId64 " \n",m);
 for(int i=0;i < dim;i++){
  svals[i] = m / primes[i];
 }
 clock_t t;
 t  = clock();
 for(int i=0;i < dim;i++){
  smvals[i] = modInverse(svals[i], primes[i]);
  printf("sm %" PRId64 " \n", smvals[i]);
 }
 t = clock() - t;
 double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds
 printf("Finding modular inverses took %f seconds. \n", time_taken);

// for(int ii=59;ii>0;ii--){
//  int* rns = malloc(sizeof(int)*dim);
//  get_rns(ii,primes,rns,dim);
//  printf("%d: %d \n",ii, get_integer(rns,dim,primes,m,svals,smvals));
//  free(rns);
// }

//  int i = 0;
//  while(i < 100){
   u_int64_t* rnsa = (u_int64_t*)malloc(sizeof(u_int64_t*)*dim);
   u_int64_t* rnsb = (u_int64_t*)malloc(sizeof(u_int64_t*)*dim);
   u_int64_t* rnsc = (u_int64_t*)malloc(sizeof(u_int64_t*)*dim);

//   int opa = get_random_number() % 59;
   int opa = 100;
   printf("%d+",opa);
//   int opb = get_random_number() % 59;
   int opb = 200;
   printf("%d= ",opb);
   while(opb == 0)opb = get_random_number() % 59;
   get_rns(opa,primes,rnsa,dim);
   get_rns(opb,primes,rnsb,dim);
   addrns(rnsa,rnsb,rnsc, dim, primes);
//   divrns(rnsa,rnsb,rnsc, dim, primes);

   printf("%d \n",get_integer(rnsc,dim,primes,m,svals,smvals));

   free(rnsc);
   free(rnsb);
   free(rnsa);
//   i++;
// }

}
