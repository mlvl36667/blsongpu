#ifndef UTILS
#define UTILS

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

uint64_t get_integer(uint64_t* ,int ,uint64_t* ,uint64_t ,uint64_t* ,uint64_t* );
void get_rns(uint64_t , uint64_t* , uint64_t* ,int );
uint64_t modInverse(uint64_t , uint64_t );
void addrns(uint64_t* ,uint64_t* ,uint64_t* , int , uint64_t* );
void mulrns(uint64_t* ,uint64_t* ,uint64_t* , int , uint64_t* );
void divrns(uint64_t* ,uint64_t* ,uint64_t* , int , uint64_t* );
int get_random_number();
uint64_t power(uint64_t , uint64_t );
#endif
