// compile with nime nvcc -o sign sign.cu  -rdc=false -Xptxas -v  -O0  -lineinfo --ptxas-options=-O0
// /usr/bin/c++ -DSODIUM_STATIC -I/home/urllc2/bls-signatures/src -I/home/urllc2/bls-signatures/build/_deps/relic-src/include -I/home/urllc2/bls-signatures/build/_deps/relic-build/include -I/home/urllc2/bls-signatures/build/_deps/sodium-src/libsodium/src/libsodium/include -O3 -DNDEBUG -fPIE -std=gnu++17 -MD -MT main.cpp.o -MF main.cpp.o.d -o main.cpp.o -c main.cpp; /usr/bin/c++ -O3 -DNDEBUG main.cpp.o -o runmain  /home/urllc2/bls-signatures/build/src/libbls.a /home/urllc2/bls-signatures/build/_deps/relic-build/lib/librelic_s.a /usr/lib/x86_64-linux-gnu/libgmp.so -lrt -lpthread -lm /home/urllc2/bls-signatures/build/_deps/sodium-build/libsodium.a
//  sudo apt-get purge nvidia*
//  sudo apt-get autoremove
//  sudo reboot
//  lsmod | grep nvidia.drm
//  sudo sh cuda_12.0.0_525.60.13_linux.run
//  sudo /usr/local/NVIDIA-Nsight-Compute-2022.4/ncu --call-stack -f --set detailed -k saxpy -o res ./sign --metrics gpu__time_duration.sum

#include <stdio.h>
#include <malloc.h>
#include <time.h>

#include <inttypes.h>
#include <stdint.h>
#include<string.h>
#include <stdarg.h>
#include <ctype.h>


#define NBLOCKS 1
#define NTHREADS 1

#define INLINE 0
/** Prime field size in bits. */
#define FP_PRIME 381
#define RLC_BN_SIZE 8
#define RLC_DIG 64
#define fp_null(A)                      /* empty */
#define fp_new(A)                       /* empty */
#define bn_null(A)                      /* empty */
#define BASIC    1
#define FP_RDC   BASIC
#define PROJC    2
/** Use -1 as quadratic non-residue. */
#define FP_QNRES


/** Size of word in this architecture. */
#define WSIZE    64

//#define RLC_FP_DIGS             (FP_PRIME/WSIZE + 1)
/**
 * Computes the ceiling function of an integer division.
 *
 * @param[in] A                 - the dividend.
 * @param[in] B                 - the divisor.
 */
#define RLC_CEIL(A, B)                  (((A) - 1) / (B) + 1)
/**
 * Returns the given character in upper case.
 *
 * @param[in] C                 - the character. 
 */
#define RLC_UPP(C)                              ((C) - 0x20 * (((C) >= 'a') && ((C) <= 'z')))
/**
 * Precision in bits of a prime field element.
 */
#define RLC_FP_BITS     ((int)FP_PRIME)
/**
 * Size in digits of a block sufficient to store a prime field element.
 */
#define RLC_FP_DIGS     ((int)RLC_CEIL(RLC_FP_BITS, RLC_DIG))
/**
 * Size in bytes of a block sufficient to store a binary field element.
 */
#define RLC_FP_BYTES    ((int)RLC_CEIL(RLC_FP_BITS, 8))
/**
 * Maximum number of coefficients of an isogeny map polynomial.
 * 4 is sufficient for a degree-3 isogeny polynomial.
 */
#define RLC_EPX_CTMAP_MAX       4
#define BASIC    1
/** @{ */
#define B12_P381_A0             "0"
#define B12_P381_A1             "0"
#define B12_P381_B0             "4"
#define B12_P381_B1             "4"
#define B12_P381_X0             "024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8"
#define B12_P381_X1             "13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E"
#define B12_P381_Y0             "0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801"
#define B12_P381_Y1             "0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE"
#define B12_P381_R              "73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001"
#define B12_P381_H              "5D543A95414E7F1091D50792876A202CD91DE4547085ABAA68A205B2E5A7DDFA628F1CB4D9E82EF21537E293A6691AE1616EC6E786F0C70CF1C38E31C7238E5"
#define B12_P381_ISO_A0 "0"
#define B12_P381_ISO_A1 "F0"
#define B12_P381_ISO_B0 "3F4"
#define B12_P381_ISO_B1 "3F4"
#define B12_P381_ISO_XN "5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6,5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6;0,11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a;11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e,8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d;171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1,0"
#define B12_P381_ISO_XD "0,1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63;c,1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f;1,0"
#define B12_P381_ISO_YN "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706,1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706;0,5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be;11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c,8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f;124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10,0"
#define B12_P381_ISO_YD "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb,1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb;0,1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3;12,1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99;1,0"
#define B12_P381_MAPU0 "-2"
#define B12_P381_MAPU1 "-1"
__device__
#if INLINE == 0
__noinline__
#endif
void print_multiple_precision(const uint64_t *number, int size){
// This function prints a multiple precision integer stored as uint64_t
  for(int i=0; i < size; i++){
   printf("%" PRIu64 "\n", number[i]);
  }
}
__device__
#if INLINE == 0
__noinline__
#endif
void print_line(){
// This function prints a line
  printf("\n-----------------\n");
}
/** @} */
__device__ 
__noinline__
inline static unsigned int lzcnt64_generic(unsigned long long x)
{
    unsigned int n;
    static unsigned int clz_table_4[] = {
        0,
        4,
        3, 3,
        2, 2, 2, 2,
        1, 1, 1, 1, 1, 1, 1, 1
    };

    if (x == 0) {
        return sizeof(x)*8;
    }

    n = clz_table_4[x >> (sizeof(x)*8 - 4)];
    if (n == 0) {
        if ((x & ((unsigned long long)0xFFFFFFFF << 32)) == 0) { n  = 32; x <<= 32; }
        if ((x & ((unsigned long long)0xFFFF0000 << 32)) == 0) { n += 16; x <<= 16; }
        if ((x & ((unsigned long long)0xFF000000 << 32)) == 0) { n += 8;  x <<= 8;  }
        if ((x & ((unsigned long long)0xF0000000 << 32)) == 0) { n += 4;  x <<= 4;  }
        n += clz_table_4[x >> (sizeof(x)*8 - 4)];
    }

    return n - 1;
}
__device__ 
__noinline__
unsigned int lzcnt32_generic(unsigned int x)
{
    unsigned int n; 
    static unsigned int clz_table_4[] = {
        0,
        4, 
        3, 3, 
        2, 2, 2, 2, 
        1, 1, 1, 1, 1, 1, 1, 1
    };

    if (x == 0) {
        return sizeof(x)*8;
    }

    n = clz_table_4[x >> (sizeof(x)*8 - 4)];
    if (n == 0) {
        if ((x & 0xFFFF0000) == 0) { n  = 16; x <<= 16; }
        if ((x & 0xFF000000) == 0) { n += 8;  x <<= 8;  }
        if ((x & 0xF0000000) == 0) { n += 4;  x <<= 4;  }
        n += clz_table_4[x >> (sizeof(x)*8 - 4)];
    }
    return n - 1;
}
/**
 * Returns the minimum between two numbers.
 *
 * @param[in] A         - the first number.
 * @param[in] B         - the second number.
 */
#define RLC_MIN(A, B)                   ((A) < (B) ? (A) : (B))
/**
 * Negative sign of a multiple precision integer.
 */
#define RLC_NEG         1
/**
 * Returns the maximum between two numbers.
 *
 * @param[in] A         - the first number.
 * @param[in] B         - the second number.
 */
#define RLC_MAX(A, B)                   ((A) > (B) ? (A) : (B))
#define FB_POLYN 283
#define RLC_DV_MAX              (FB_POLYN)
/** Irreducible polynomial size in bits. */
//#define RLC_DV_DIGS             (RLC_MAX(RLC_CEIL(RLC_DV_MAX, RLC_DIG), RLC_BN_SIZE))
#define RLC_DV_DIGS             (2 * RLC_FP_DIGS + 1)
/**
 * List of possible errors generated by the library.
 */             
enum errors {   
        /** Constant to indicate the first an error already catched. */
        ERR_CAUGHT = 1,
        /** Occurs when memory-allocating functions fail. */
        ERR_NO_MEMORY,
        /** Occcurs when the library precision is not sufficient. */
        ERR_NO_PRECI,
        /** Occurs when a file is not found. */
        ERR_NO_FILE,
        /** Occurs when the specified number of bytes cannot be read from source. */
        ERR_NO_READ,
        /** Occurs when an invalid value is passed as input. */
        ERR_NO_VALID,
        /** Occurs when a buffer capacity is insufficient. */
        ERR_NO_BUFFER,  
        /** Occurs when there is not a supported field in the security level. */
        ERR_NO_FIELD,
        /** Occurs when there is not a supported curve in the security level. */
        ERR_NO_CURVE,
        /** Occurs when the library configuration is incorrect. */
        ERR_NO_CONFIG,
        /** Occurs when the PRNG is stuck at one value. */
        ERR_NO_RAND,
        /** Constant to indicate the number of errors. */
        ERR_MAX
};

/**     
 * Indicates that the function executed correctly.
 */     
#define RLC_OK                  0

/**     
 * Indicates that an error occurred during the function execution.
 */     
#define RLC_ERR                 1 
                
/**     
 * Indicates that a comparison returned that the first argument was lesser than
 * the second argument.
 */
#define RLC_LT                  -1
        
/**
 * Indicates that a comparison returned that the first argument was equal to
 * the second argument.
 */     
#define RLC_EQ                  0
        
/**
 * Indicates that a comparison returned that the first argument was greater than
 * the second argument.
 */     
#define RLC_GT                  1

/**
 * Indicates that two incomparable elements are not equal.
 */
#define RLC_NE                  2

/**
 * Optimization identifer for the case where a coefficient is 0.
 */
#define RLC_ZERO                0

/** 
 * Optimization identifer for the case where a coefficient is 1.
 */ 
#define RLC_ONE                 1
    
/** 
 * Optimization identifer for the case where a coefficient is 2.
 */
#define RLC_TWO                 2
typedef uint64_t dig_t;
typedef __uint128_t dbl_t;
typedef dig_t *fp_t;
typedef dig_t *dv_t;
#define RLC_PAD(A)              (0)
/**
 * Represents a prime field element with automatic memory allocation.
 */
typedef dig_t fp_st[RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)];
/**
 * Maximum number of coefficients of an isogeny map polynomial.
 * RLC_TERMS of value 16 is sufficient for a degree-11 isogeny polynomial.
 */
#define RLC_EP_CTMAP_MAX                16
/**
 * Represents a quadratic extension prime field element.
 *
 * This extension is constructed with the basis {1, i}, where i is an adjoined
 * square root in the prime field.
 */
typedef fp_t fp2_t[2];
/**
 * Coefficients of an isogeny map for a curve over a quadratic extension.
 */
typedef struct {
        /** The a-coefficient of the isogenous curve used for SSWU mapping. */
        fp2_t a;
        /** The b-coefficient of the isogenous curve used for SSWU mapping. */
        fp2_t b;
        /** Degree of x numerator */
        int deg_xn;
        /** Degree of x denominator */
        int deg_xd;
        /** Degree of y numerator */
        int deg_yn;
        /** Degree of y denominator */
        int deg_yd;
        /** x numerator coefficients */
        fp2_t xn[RLC_EPX_CTMAP_MAX];
        /** x denominator coefficients */
        fp2_t xd[RLC_EPX_CTMAP_MAX];
        /** y numerator coefficients */
        fp2_t yn[RLC_EPX_CTMAP_MAX];
        /** y denominator coefficients */
        fp2_t yd[RLC_EPX_CTMAP_MAX];
} iso2_st;
/**
 * Pointer to isogeny map coefficients.
 */
typedef iso2_st *iso2_t;
/**
 * Represents an elliptic curve point over a quadratic extension over a prime
 * field.
 */
typedef struct {
        /** The first coordinate. */
        fp2_t x;
        /** The second coordinate. */
        fp2_t y;
        /** The third coordinate (projective representation). */
        fp2_t z;
        /** Flag to indicate the coordinate system of this point. */
        int coord;
} ep2_st;
typedef ep2_st *ep2_t;
__device__
#if INLINE == 0
__noinline__
#endif
int util_bits_dig(dig_t a) {
    return RLC_DIG - lzcnt64_generic(a);
}
/**
 * Represents a multiple precision integer.
 *
 * The field dp points to a vector of digits. These digits are organized
 * in little-endian format, that is, the least significant digits are
 * stored in the first positions of the vector.
 */
typedef struct {
        /** The number of digits allocated to this multiple precision integer. */
        int alloc;
        /** The number of digits actually used. */
        int used;
        /** The sign of this multiple precision integer. */
        int sign;
        dig_t *dp;
} bn_st;
typedef bn_st *bn_t;
/**
 * Positive sign of a multiple precision integer.
 */
#define RLC_POS         0

#define gpuErrChk(ans) { gpuAssert((ans), __FILE__, __LINE__); }
inline void gpuAssert(cudaError_t code,
                      const char *file,
                      int line,
                      bool abort=true) {
  if (code != cudaSuccess) {
    fprintf(stderr,"GPUassert: %s %s %d\n",
            cudaGetErrorString(code), file, line);
    exit(code);
  }
}

__device__ __constant__ dig_t fp_prime[10];
//////////////////////////////////////////////////////////////
// CUDA shared memory declarations and static allocation    //
  __shared__ dig_t* shared_u;
  __shared__ dig_t shared_m[10];
  __shared__ dig_t shared_prime[10];
  __shared__ bn_t shared_prime_bn;
  __shared__ dig_t shared_one[10];
  __shared__ dig_t shared_conv[10];
  __shared__ fp_t shared_a[10];
  __shared__ fp_t shared_b[10];
  __shared__ fp2_t shared_map_u;
  __shared__ fp2_t shared_c[4];
  __shared__ iso2_t shared_coeffs;
//////////////////////////////////////////////////////////////
/**
 * Multiplies two digits to give a double precision result.
 *
 * @param[out] H                - the higher half of the result.
 * @param[out] L                - the lower half of the result.
 * @param[in] A                 - the first digit to multiply.
 * @param[in] B                 - the second digit to multiply.
 */
#define RLC_MUL_DIG(H, L, A, B)                     \
        H = ((dbl_t)(A) * (dbl_t)(B)) >> RLC_DIG;   \
        L = (A) * (B);                              \
/**
 * Accumulates a single precision digit in a triple register variable.
 *
 * @param[in,out] T                     - the temporary variable.
 * @param[in,out] R2            - most significant word of the triple register.
 * @param[in,out] R1            - middle word of the triple register.
 * @param[in,out] R0            - lowest significant word of the triple register.
 * @param[in] A                         - the first digit to accumulate.
 */
#define RLC_COMBA_ADD(T, R2, R1, R0, A)  \
        (T) = (R1);                      \
        (R0) += (A);                     \
        (R1) += (R0) < (A);              \
        (R2) += (R1) < (T);              \


/**     
 * Accumulates a double precision digit in a triple register variable.
 *
 * @param[in,out] R2            - most significant word of the triple register.
 * @param[in,out] R1            - middle word of the triple register.
 * @param[in,out] R0            - lowest significant word of the triple register.
 * @param[in] A                         - the first digit to multiply.
 * @param[in] B                         - the second digit to multiply.
 */             
#define RLC_COMBA_STEP_MUL(R2, R1, R0, A, B)  \
        dig_t _r, _r0, _r1;                   \
        RLC_MUL_DIG(_r1, _r0, A, B);          \
        RLC_COMBA_ADD(_r, R2, R1, R0, _r0);   \
        (R1) += _r1;                          \
        (R2) += (R1) < _r1;                   \


/**
 * Returns a bit mask to isolate the lowest part of a digit.
 *
 * @param[in] B                 - the number of bits to isolate.
 */
#define RLC_MASK(B)                                                                                                                     \
        ((-(dig_t)((B) >= WSIZE)) | (((dig_t)1 << ((B) % WSIZE)) - 1))
#define RLC_TRY                                 if (1)
#define RLC_CATCH_ANY                   if (0)
#define RLC_THROW                               printf("error thrown in operation...\n")
#define RLC_FINALLY                             if (1)
#define RLC_DIG_LOG             6
/**
 * Splits a bit count in a digit count and an updated bit count.
 *              
 * @param[out] B                - the resulting bit count.
 * @param[out] D                - the resulting digit count.
 * @param[out] V                - the bit count.
 */
#define RLC_RIP(B, D, V)                                                                                                        \
        D = (V) >> (RLC_DIG_LOG); B = (V) - ((D) * (1 << RLC_DIG_LOG));
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
__device__
#if INLINE == 0
__noinline__
#endif
void dv_copy(dig_t *c, const dig_t *a, int digits) {
//        printf("now copying data: %d \n ", digits);
        memcpy(c, a, digits * sizeof(dig_t));
//        printf("data copied data: %d \n", digits);
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t* cuda_realloc(int oldsize, int newsize, dig_t* old)
{
    dig_t* newT = (dig_t*) malloc (newsize*sizeof(dig_t));
    for(int i=0; i<oldsize; i++)
    {
        newT[i] = old[i];
    }

    free(old);
    return newT;
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_grow(bn_t a, int digits) {
//#if ALLOC == DYNAMIC
        dig_t *t;

        if (a->alloc < digits) {
                /* At least add RLC_BN_SIZE more digits. */
                digits += (RLC_BN_SIZE * 2) - (digits % RLC_BN_SIZE);
                t = (dig_t *)cuda_realloc(a->alloc, (RLC_DIG / 8) * digits, a->dp);
                if (t == NULL) {
                        printf("no more memory in bn_grow...\n ");
                        return;
                }
                a->dp = t;
                /* Set the newly allocated digits to zero. */
                a->alloc = digits;
        }
//#elif ALLOC == AUTO
//        if (digits > RLC_BN_SIZE) {
//                printf("bn_grow error, RLC_BN_SIZE: %d digits: %d .... \n", RLC_BN_SIZE, digits);
//                return;
//        }
//        (void)a;
//#endif
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_copy(bn_t c, const bn_t a) {
        if (c->dp == a->dp) {
                return;
        }
        bn_grow(c, a->used);
        dv_copy(c->dp, a->dp, a->used);
        c->used = a->used;      
        c->sign = a->sign;
}
__device__
#if INLINE == 0
__noinline__
#endif
void dv_lshd(dig_t *c, const dig_t *a, int size, int digits) {
        dig_t *top;
        const dig_t *bot;
        int i;
        top = c + size - 1;
        bot = a + size - 1 - digits;

        for (i = 0; i < size - digits; i++, top--, bot--) {
                *top = *bot;
        }
        for (i = 0; i < digits; i++, c++) {
                *c = 0;
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t bn_lshb_low(dig_t *c, const dig_t *a, int size, int bits) {
        int i;
        dig_t r, carry, shift, mask;

//        printf("now in bn_lshb_low...\n");
//        printf("bits: %d ...\n", bits);
        shift = RLC_DIG - bits;
//       printf("a: %" PRIu64 "\n", *a); 
//       printf("shift: %" PRIu64 "\n", shift);

        carry = 0;
        mask = RLC_MASK(bits);
//      printf("mask: %" PRIu64 "\n", mask);

        for (i = 0; i < size; i++, a++, c++) {
                /* Get the needed least significant bits. */
                r = ((*a) >> shift) & mask;
                /* Shift left the operand. */
                *c = ((*a) << bits) | carry;

//                printf("c: %" PRIu64 "\n", *c);
 

                /* Update the carry. */
                carry = r;
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_trim(bn_t a) {
        if (a->used <= a->alloc) {
                while (a->used > 0 && a->dp[a->used - 1] == 0) {
                        --(a->used);
                }
                /* Zero can't be negative. */
                if (a->used <= 0) {
                        a->used = 1;
                        a->dp[0] = 0;
                        a->sign = RLC_POS;
                }
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_lsh(bn_t c, const bn_t a, int bits) {
        int digits;
        dig_t carry;
        bn_copy(c, a);
        if (bits <= 0) {
                return;
        }
        RLC_RIP(bits, digits, bits);
        bn_grow(c, c->used + digits + (bits > 0));
        c->used = a->used + digits;
        c->sign = a->sign;
        if (digits > 0) {
         dv_lshd(c->dp, a->dp, c->used, digits);
        }
        if (bits > 0) {
         if (c != a) {
          carry = bn_lshb_low(c->dp + digits, a->dp, a->used, bits);
         } else {
         carry = bn_lshb_low(c->dp + digits, c->dp + digits, c->used - digits, bits);
         }
          if (carry != 0) {
           c->dp[c->used] = carry;
           (c->used)++;
          }
         }
         bn_trim(c);
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t fp_addn_low(dig_t *c, const dig_t *a, const dig_t *b) {
        int i;
        dig_t carry, c0, c1, r0, r1;
        carry = 0;
        for (i = 0; i < RLC_FP_DIGS; i++, a++, b++, c++) {
                r0 = (*a) + (*b);
                c0 = (r0 < (*a));
                r1 = r0 + carry;
                c1 = (r1 < r0);
                carry = c0 | c1;
                (*c) = r1;
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_subm_low(dig_t *c, const dig_t *a, const dig_t *b) {
        int i;
        dig_t carry, r0, diff;

        /* Zero the carry. */
        carry = 0;
        for (i = 0; i < RLC_FP_DIGS; i++, a++, b++) {
                diff = (*a) - (*b);
                r0 = diff - carry;
                carry = ((*a) < (*b)) || (carry && !diff);
                c[i] = r0;
        }
        if (carry) {
                fp_addn_low(c, c, shared_prime);
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_sub(fp_t c, const fp_t a, const fp_t b) {
        fp_subm_low(c, a, b);
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t fp_subn_low(dig_t *c, const dig_t *a, const dig_t *b) {
        int i;
        dig_t carry, r0, diff;

      //  printf("calling fp_subn_low...\n");
        /* Zero the carry. */
        carry = 0;
        for (i = 0; i < RLC_FP_DIGS; i++, a++, b++, c++) {
                diff = (*a) - (*b);
                r0 = diff - carry;
                carry = ((*a) < (*b)) || (carry && !diff);
                (*c) = r0;
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
int dv_cmp(const dig_t *a, const dig_t *b, int size) {
        int i, r;
        a += (size - 1);
        b += (size - 1);
        r = RLC_EQ;
        for (i = 0; i < size; i++, --a, --b) {
                if (*a != *b && r == RLC_EQ) {
                        r = (*a > *b ? RLC_GT : RLC_LT);
                }
        }
        return r;
}
__device__
#if INLINE == 0
__noinline__
#endif
void dv_zero(dig_t *a, int digits) {
        int i;
        for (i = 0; i < digits; i++, a++) {
                (*a) = 0;
        }
        return;
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_zero(bn_t a) {
        a->sign = RLC_POS;
        a->used = 1;
        dv_zero(a->dp, a->alloc);
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_set_dig(bn_t a, dig_t digit) {
        bn_zero(a);
        a->dp[0] = digit;
        a->used = 1;
        a->sign = RLC_POS;
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_mod_pre_monty(bn_t u, const bn_t m) {
// Even though the algorithm works for any r which is relatively prime to n, it is more useful when r is taken to be a power of 2. In this case, the Montgomery algorithm performs divisions by a power of 2, which is an intrinsically fast operation on general-purpose computers, e.g., signal processors and microprocessors; this leads to a simpler implementation than ordinary modular multiplication, which is typically faster as well [7].

 dig_t x, b;
 b = m->dp[0];

 if ((b & 0x01) == 0) {
  printf("+++++++++ Error +++++++++ \n");
  printf("(b & 0x01) == 0 in bn_mod_pre_monty ...\n");
  printf("++++++++ !Error! ++++++++++ \n");
  return;
 }

 x = (((b + 2) & 4) << 1) + b;                           /* here x*a==1 mod 2**4 */
 x *= (dig_t)2 - b * x;                                          /* here x*a==1 mod 2**8 */
 x *= (dig_t)2 - b * x;                                          /* here x*a==1 mod 2**16 */
 x *= (dig_t)2 - b * x;                                          /* here x*a==1 mod 2**32 */
 x *= (dig_t)2 - b * x;                                          /* here x*a==1 mod 2**64 */
 /* u = -1/m0 (mod 2^RLC_DIG) */
 bn_set_dig(u, -x);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_rdcn_low(dig_t *c, dig_t *a) {
 int i, j;
 dig_t t, r0, r1, r2, *tmp, *tmpc, u;
 const dig_t *tmpm, *m;
 //   u = *(fp_prime_get_rdc());
 //   m = fp_prime_get();
 u = *shared_u;
 m = shared_prime;

// printf("u in fp_rdcn_low: \n");
// print_multiple_precision(&u,6);
// print_line();
//
// printf("m in fp_rdcn_low: \n");
// print_multiple_precision(m,6);
// print_line();

 printf("a in fp_rdcn_low: \n");
 print_multiple_precision(a,6);
 print_line();

 tmpc = c;
 r0 = r1 = r2 = 0;
 for (i = 0; i < RLC_FP_DIGS; i++, tmpc++, a++) {
  tmp = c;
  tmpm = m + i;
  for (j = 0; j < i; j++, tmp++, tmpm--) {
   RLC_COMBA_STEP_MUL(r2, r1, r0, *tmp, *tmpm);
  }
  RLC_COMBA_ADD(t, r2, r1, r0, *a);
  *tmpc = (dig_t)(r0 * u);
  RLC_COMBA_STEP_MUL(r2, r1, r0, *tmpc, *m);
  r0 = r1;
  r1 = r2;
  r2 = 0;
 }
 for (i = RLC_FP_DIGS; i < 2 * RLC_FP_DIGS - 1; i++, a++) {
  tmp = c + (i - RLC_FP_DIGS + 1);
  tmpm = m + RLC_FP_DIGS - 1;
  for (j = i - RLC_FP_DIGS + 1; j < RLC_FP_DIGS; j++, tmp++, tmpm--) {
   RLC_COMBA_STEP_MUL(r2, r1, r0, *tmp, *tmpm);
  }
  RLC_COMBA_ADD(t, r2, r1, r0, *a);
  c[i - RLC_FP_DIGS] = r0;
  r0 = r1;
  r1 = r2;
  r2 = 0;
  }
  RLC_COMBA_ADD(t, r2, r1, r0, *a);
  c[RLC_FP_DIGS - 1] = r0;
  if (r1 || dv_cmp(c, m, RLC_FP_DIGS) != RLC_LT) {
   fp_subn_low(c, c, m);
  }
}
// Function to multiply two integers
__device__
#if INLINE == 0
__noinline__
#endif
void fp_muln_low(dig_t *c, const dig_t *a, const dig_t *b) {
        int i, j;
        const dig_t *tmpa, *tmpb;
        dig_t r0, r1, r2;
// printf("input in fp_muln_low...\n ");
// printf("a: %" PRIu64 "\n", *a);
// printf("b: %" PRIu64 "\n", *b);
        r0 = r1 = r2 = 0;
        for (i = 0; i < RLC_FP_DIGS; i++, c++) {
                tmpa = a;
                tmpb = b + i;
                for (j = 0; j <= i; j++, tmpa++, tmpb--) {
                        RLC_COMBA_STEP_MUL(r2, r1, r0, *tmpa, *tmpb);
                }
//                printf("1. setting r0 to: %" PRIu64 "\n", r0);
                *c = r0;
                r0 = r1;
                r1 = r2;
                r2 = 0;
        }
        for (i = 0; i < RLC_FP_DIGS; i++, c++) {
                tmpa = a + i + 1;
                tmpb = b + (RLC_FP_DIGS - 1);
                for (j = 0; j < RLC_FP_DIGS - (i + 1); j++, tmpa++, tmpb--) {
                        RLC_COMBA_STEP_MUL(r2, r1, r0, *tmpa, *tmpb);
                }
//                printf("2. setting r0 to: %" PRIu64 "\n", r0);
                *c = r0;
                r0 = r1;
                r1 = r2;
                r2 = 0;
        }
// printf("result at fp_muln_low: %" PRIu64 "\n", *c);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_mulm_low(dig_t *c, const dig_t *a, const dig_t *b) {
// The results has more bits then the operands...
        dig_t *t;
        t = (dig_t* ) malloc(2 * RLC_FP_DIGS * sizeof(dig_t));
// Multiply the two numbers
        fp_muln_low(t, a, b);
// Reduce the result using c
        fp_rdcn_low(c, t);
        free(t);
}
__device__
#if INLINE == 0
__noinline__
#endif
uint64_t bn_rshb_low(uint64_t *c, const uint64_t *a, int size, int bits) {
        int i;
        uint64_t r, carry, shift, mask;
        c += size - 1;
        a += size - 1;
        /* Prepare the bit mask. */
        shift = (RLC_DIG - bits) % RLC_DIG;
        carry = 0;
        mask = RLC_MASK(bits);
        for (i = size - 1; i >= 0; i--, a--, c--) {
                /* Get the needed least significant bits. */
                r = (*a) & mask;
                /* Shift left the operand. */
                *c = ((*a) >> bits) | (carry << shift);
                /* Update the carry. */
                carry = r;
        }
        return carry;
}

__device__
#if INLINE == 0
__noinline__
#endif
uint64_t add_multiple_precision_1(uint64_t *c, const uint64_t *a, uint64_t digit, int size) {
        int i;
        register uint64_t carry, r0;

        carry = digit;
        for (i = 0; i < size && carry; i++, a++, c++) {
                r0 = (*a) + carry;
                carry = (r0 < carry);
                (*c) = r0;
        }
        for (; i < size; i++, a++, c++) {
                (*c) = (*a);
        }
        return carry;
}

__device__
#if INLINE == 0
__noinline__
#endif
uint64_t add_multiple_precision(uint64_t *c, const uint64_t *a, const uint64_t *b, int size) {
        int i;
        register uint64_t carry, c0, c1, r0, r1;

        carry = 0;
        for (i = 0; i < size; i++, a++, b++, c++) {
                r0 = (*a) + (*b);
                c0 = (r0 < (*a));
                r1 = r0 + carry;
                c1 = (r1 < r0);
                carry = c0 | c1;
                (*c) = r1;
        }
        return carry;
}

__device__
#if INLINE == 0
__noinline__
#endif
uint64_t subtract_multiple_precision_1(uint64_t *c, const uint64_t *a, uint64_t digit, int size) {
        int i;
        uint64_t carry, r0;

        carry = digit;
        for (i = 0; i < size && carry; i++, c++, a++) {
                r0 = (*a) - carry;
                carry = (r0 > (*a));
                (*c) = r0;
        }
        for (; i < size; i++, a++, c++) {
                (*c) = (*a);
        }
        return carry;
}

__device__
#if INLINE == 0
__noinline__
#endif
uint64_t multiply_multiple_precision(uint64_t *c, const uint64_t *a, uint64_t digit, int size) {
        uint64_t r0, r1, carry = 0;
        for (int i = 0; i < size; i++, a++, c++) {
                r1 = ((__uint128_t)(*a) * (__uint128_t)(digit)) >> 64;
                r0 = ( *a) * (digit); 
                *c = r0 + carry;
                carry = r1 + (*c < carry);
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
void right_shift(uint64_t *c, const uint64_t *a, int size, int digits) {
        const uint64_t *top;
        uint64_t *bot;
        int i;

        top = a + digits;
        bot = c;

        for (i = 0; i < size - digits; i++, top++, bot++) {
                *bot = *top;
        }
        for (; i < size; i++, bot++) {
                *bot = 0;
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void left_shift(uint64_t *result, const uint64_t *input, int size, int digits){
// This function left shifts bits
//        uint64_t *top;
//        const dig_t *bot;
//        int i;
//
//        top = c + size - 1;
//        bot = a + size - 1 - digits;
//
//        for (i = 0; i < size - digits; i++, top--, bot--) {
//                *top = *bot;
//        }
//        for (i = 0; i < digits; i++, c++) {
//                *c = 0;
//        }
 uint64_t *top;
 const uint64_t *bot;
 top = result + size - 1;
 bot = input + size - 1 - digits;
 for (int i = 0; i < size - digits; i++, top--, bot--) {
         *top = *bot;
 }
 for (int i = 0; i < digits; i++, result++) {
         *result = 0;
 }
}
__device__
#if INLINE == 0
__noinline__
#endif
uint64_t shift_bits(uint64_t *result, const uint64_t *input, int size, int bits){
// This function shifts bits

//         int i;
//         dig_t r, carry, shift, mask;
//                 
//         shift = RLC_DIG - bits; 
//         carry = 0;
//         mask = RLC_MASK(bits);
// 
//         for (i = 0; i < size; i++, a++, c++) {
//                 /* Get the needed least significant bits. */
//                 r = ((*a) >> shift) & mask;
//                 /* Shift left the operand. */
//                 *c = ((*a) << bits) | carry;
//                 /* Update the carry. */
//                 carry = r;
//         }
//         return carry;
 uint64_t r, carry, shift, mask;
 
/**
 * Size in bits of a digit.
 */
 shift = 64 - bits;
 carry = 0;
 if(bits > 64){
  printf("shift_bits cannot shift this much, exciting...\n");
  return;
 }
 mask = (((uint64_t)1 << ((bits) % 64)) - 1);
 for (int i = 0; i < size; i++, input++, result++) {
         r = ((*input) >> shift) & mask;
         *result = ((*input) << bits) | carry;
         carry = r;
 }
 return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
int compare_multiple_precision(uint64_t *a, uint64_t *b, int size){
// Returns 1 if a > b, returns 0 if a == b, returns 2 if b > a
        int i, r;

        a += (size - 1);
        b += (size - 1);

        r = 0;
        for (i = 0; i < size; i++, --a, --b) {
                if (*a != *b && r == 0) {
                        r = (*a > *b ? 1 : 2);
                }
        }
        return r;
}
__device__
#if INLINE == 0
__noinline__
#endif
int subtract_multiple_precision(uint64_t *c, const uint64_t *a, const uint64_t *b, int size){
// a - b
        int i;
        uint64_t carry, r0, diff;

        /* Zero the carry. */
        carry = 0;
        for (i = 0; i < size; i++, a++, b++, c++) {
                diff = (*a) - (*b);
                r0 = diff - carry;
                carry = ((*a) < (*b)) || (carry && !diff);
                (*c) = r0;
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t bn_subn_low(dig_t *c, const dig_t *a, const dig_t *b, int size) {
        int i;
        dig_t carry, r0, diff;

        /* Zero the carry. */
        carry = 0;
        for (i = 0; i < size; i++, a++, b++, c++) {
                diff = (*a) - (*b);
                r0 = diff - carry;
                carry = ((*a) < (*b)) || (carry && !diff);
                (*c) = r0;
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_modn_low(dig_t *c, const dig_t *a, int sa, const dig_t *m, int sm, dig_t u) {
        int i, j;
        dig_t t, r0, r1, r2;
        dig_t *tmp, *tmpc;
        const dig_t *tmpm;

        tmpc = c;

        r0 = r1 = r2 = 0;
        for (i = 0; i < sm; i++, tmpc++, a++) {
                tmp = c;
                tmpm = m + i;
                for (j = 0; j < i; j++, tmp++, tmpm--) {
                        RLC_COMBA_STEP_MUL(r2, r1, r0, *tmp, *tmpm);
                }
                if (i < sa) {
                        RLC_COMBA_ADD(t, r2, r1, r0, *a);
                }
                *tmpc = (dig_t)(r0 * u);
                RLC_COMBA_STEP_MUL(r2, r1, r0, *tmpc, *m);
                r0 = r1;
                r1 = r2;
                r2 = 0;
        }
        for (i = sm; i < 2 * sm - 1; i++, a++) {
                tmp = c + (i - sm + 1);
                tmpm = m + sm - 1;
                for (j = i - sm + 1; j < sm; j++, tmp++, tmpm--) {
                        RLC_COMBA_STEP_MUL(r2, r1, r0, *tmp, *tmpm);
                }
                if (i < sa) {
                        RLC_COMBA_ADD(t, r2, r1, r0, *a);
                }
                c[i - sm] = r0;
                r0 = r1;
                r1 = r2;
                r2 = 0;
        }

        if (i < sa) {
                RLC_COMBA_ADD(t, r2, r1, r0, *a);
        }
        c[sm - 1] = r0;
        if (r1) {
                bn_subn_low(c, c, m, sm);
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
int bn_is_zero(const bn_t a) {
        if (a->used == 0) {
                return 1;
        }
        if ((a->used == 1) && (a->dp[0] == 0)) {
                return 1;
        }
        return 0;
}
__device__
#if INLINE == 0
__noinline__
#endif
int bn_cmp_abs(const bn_t a, const bn_t b) {

//        printf("Inside bn_cmp_abs...\n");
//        printf("a-> used %d ....\n", a->used);
//        printf("b-> used %d ....\n", b->used);

        if (bn_is_zero(a) && bn_is_zero(b)) {
                return RLC_EQ;
        }

        if (a->used > b->used) {
                return RLC_GT;
        }

        if (a->used < b->used) {
                return RLC_LT;
        }

        return dv_cmp(a->dp, b->dp, a->used);
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_make(bn_t a, int digits) {
        if (digits < 0) {
                printf("digits < 0 in bn_make...");
        }
        /* Allocate at least one digit. */
        digits = RLC_MAX(digits, 1);
        if (a != NULL) {
                a->used = 1;
                a->dp[0] = 0;
                a->alloc = digits;
                a->sign = RLC_POS;
        }
}
#define bn_new_size(A, D)    \
        bn_make(A, D);       \

__device__
#if INLINE == 0
__noinline__
#endif
void bn_new(bn_t t){
 bn_make(t, RLC_BN_SIZE);
}

// __device__
#if INLINE == 0
__noinline__
#endif
// void bn_mod_monty_comba(bn_t c, const bn_t a, const bn_t m, const bn_t u) {
//         int digits; 
//         bn_t t; 
// 
//         printf(" now reducing the converted message using combat monty... \n");
//         digits = 2 * m->used;
//         bn_new_size(t, digits);
//         bn_zero(t);
// 
//         bn_modn_low(t->dp, a->dp, a->used, m->dp, m->used, u->dp[0]);
//         t->used = m->used;
// 
//         bn_trim(t);
//         if (bn_cmp_abs(t, m) != RLC_LT) {
//          bn_sub(t, t, m);
//         }
//         bn_copy(c, t);
// }

__device__
#if INLINE == 0
__noinline__
#endif
void bn_abs(bn_t c, const bn_t a) {
        if (c->dp != a->dp) {
                bn_copy(c, a);
        }
        c->sign = RLC_POS;
}
__device__
#if INLINE == 0
__noinline__
#endif
int bn_sign(const bn_t a) {
        return a->sign;
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t bn_addn_low(dig_t *c, const dig_t *a, const dig_t *b, int size) {
        int i;
        register dig_t carry, c0, c1, r0, r1;

        carry = 0;
        for (i = 0; i < size; i++, a++, b++, c++) {
                r0 = (*a) + (*b);
                c0 = (r0 < (*a));
                r1 = r0 + carry;
                c1 = (r1 < r0);
                carry = c0 | c1;
                (*c) = r1;
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t bn_add1_low(dig_t *c, const dig_t *a, dig_t digit, int size) {
        int i;
        register dig_t carry, r0;

        carry = digit;
        for (i = 0; i < size && carry; i++, a++, c++) {
                r0 = (*a) + carry;
                carry = (r0 < carry);
                (*c) = r0;
        }
        for (; i < size; i++, a++, c++) {
                (*c) = (*a);
        }
        return carry;
}
/**
 * Adds two multiple precision integers, where a >= b.
 *
 * @param[out] c        - the result.
 * @param[in] a         - the first multiple precision integer to add.
 * @param[in] b         - the second multiple precision integer to add.
 */
__device__
#if INLINE == 0
__noinline__
#endif
static void bn_add_imp(bn_t c, const bn_t a, const bn_t b) {
        int max, min;
        dig_t carry;

        max = a->used;
        min = b->used;

        if (min == 0) {
                bn_copy(c, a);
                return;
        }
                /* Grow the result. */
                bn_grow(c, max);

                if (a->used == b->used) {
                        carry = bn_addn_low(c->dp, a->dp, b->dp, max);
                } else {
                        carry = bn_addn_low(c->dp, a->dp, b->dp, min);
                        carry = bn_add1_low(c->dp + min, a->dp + min, carry, max - min);
                }
                if (carry) {
                        bn_grow(c, max + 1);
                        c->dp[max] = carry;
                }
                c->used = max + carry;
                bn_trim(c);
}

__device__
#if INLINE == 0
__noinline__
#endif
dig_t bn_sub1_low(dig_t *c, const dig_t *a, dig_t digit, int size) {
        int i;
        dig_t carry, r0;

        carry = digit;
        for (i = 0; i < size && carry; i++, c++, a++) {
                r0 = (*a) - carry;
                carry = (r0 > (*a));
                (*c) = r0;
        }
        for (; i < size; i++, a++, c++) {
                (*c) = (*a);
        }
        return carry;
}


/**
 * Subtracts two multiple precision integers, where a >= b.
 *
 * @param[out] c        - the result.
 * @param[in] a         - the first multiple precision integer to subtract.
 * @param[in] b         - the second multiple precision integer to subtract.
 */
__device__
#if INLINE == 0
__noinline__
#endif
static void bn_sub_imp(bn_t c, const bn_t a, const bn_t b) {
        int max, min;
        dig_t carry;

        max = a->used;
        min = b->used;

        if (min == 0) {
                bn_copy(c, a);
                return;
        }

                /* Grow the destination to accomodate the result. */
                bn_grow(c, max);

                if (a->used == b->used) {
                        carry = bn_subn_low(c->dp, a->dp, b->dp, min);
                } else {
                        carry = bn_subn_low(c->dp, a->dp, b->dp, min);
                        carry = bn_sub1_low(c->dp + min, a->dp + min, carry, max - min);
                }
                c->used = max;
                bn_trim(c);
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_sub(bn_t c, const bn_t a, const bn_t b) {
        int sa, sb;

        sa = a->sign;
        sb = b->sign;

        if (sa != sb) {
                /* If the signs are different, copy the sign of the first number and
                 * add. */
                c->sign = sa;
                if (bn_cmp_abs(a, b) == RLC_LT) {
                        bn_add_imp(c, b, a);
                } else {
                        bn_add_imp(c, a, b);
                }
        } else {
                /* If the signs are equal, adjust the sign and subtract. */
                if (bn_cmp_abs(a, b) != RLC_LT) {
                        bn_sub_imp(c, a, b);
                        c->sign = sa;
                } else {
                        bn_sub_imp(c, b, a);
                        c->sign = (sa == RLC_POS) ? RLC_NEG : RLC_POS;
                }
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_neg(bn_t c, const bn_t a) {
        if (c->dp != a->dp) {
                bn_copy(c, a);
        }
        if (!bn_is_zero(c)) {
                c->sign = a->sign ^ 1;
        }
}

__device__
#if INLINE == 0
__noinline__
#endif
void bn_add(bn_t c, const bn_t a, const bn_t b) {
        int sa, sb;

        sa = a->sign;
        sb = b->sign;

        if (sa == sb) {
                /* If the signs are equal, copy the sign and add. */
                c->sign = sa;
                if (bn_cmp_abs(a, b) == RLC_LT) {
                        bn_add_imp(c, b, a);
                } else {
                        bn_add_imp(c, a, b);
                }
        } else {
                /* If the signs are different, subtract. */
                if (bn_cmp_abs(a, b) == RLC_LT) {
                        bn_sub_imp(c, b, a);
                        c->sign = sb;
                } else {
                        bn_sub_imp(c, a, b);
                        c->sign = sa;
                }
        }
}

__device__
#if INLINE == 0
__noinline__
#endif
void dv_rshd(dig_t *c, const dig_t *a, int size, int digits) {
        const dig_t *top;
        dig_t *bot;
        int i;
    
        top = a + digits;
        bot = c;

        for (i = 0; i < size - digits; i++, top++, bot++) {
                *bot = *top;
        }
        for (; i < size; i++, bot++) {
                *bot = 0;
        }
}
#define RLC_DIV_DIG(Q, R, H, L, D)                                                                                      \
        Q = (((dbl_t)(H) << RLC_DIG) | (L)) / (D);                                                              \
        R = (((dbl_t)(H) << RLC_DIG) | (L)) - (dbl_t)(Q) * (dbl_t)(D);                  \
 
__device__
#if INLINE == 0
__noinline__
#endif
dig_t bn_mul1_low(dig_t *c, const dig_t *a, dig_t digit, int size) {
        dig_t r0, r1, carry = 0;
        for (int i = 0; i < size; i++, a++, c++) {
                RLC_MUL_DIG(r1, r0, *a, digit);
                *c = r0 + carry;
                carry = r1 + (*c < carry);
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_divn_low(dig_t *c, dig_t *d, dig_t *a, int sa, dig_t *b, int sb) {
	int norm, i, n, t, sd;
	dig_t carry, t1[3], t2[3];

	/* Normalize x and y so that the leading digit of y is bigger than
	 * 2^(RLC_DIG-1). */


	norm = util_bits_dig(b[sb - 1]) % RLC_DIG;
//        printf("\n.B 1 ..\n");
//        for(int i=0; i < sb; i++){
//         printf ("b%d: %" PRIu64 "\n",i,  b[i]);
//        }

	if (norm < (int)(RLC_DIG - 1)) {
		norm = (RLC_DIG - 1) - norm;
		carry = bn_lshb_low(a, a, sa, norm);
		if (carry) {
			a[sa++] = carry;
		}

//        printf("\n.B 2 ..\n");
//        for(int i=0; i < sb; i++){
//         printf ("b%d: %" PRIu64 "\n",i,  b[i]);
//        }
		carry = bn_lshb_low(b, b, sb, norm);
//        printf("\n.B 3 ..\n");
//        for(int i=0; i < sb; i++){
//         printf ("b%d: %" PRIu64 "\n",i,  b[i]);
//        }


		if (carry) {
			b[sb++] = carry;
		}
	} else {
		norm = 0;
	}
//        exit(0);

	n = sa - 1;
	t = sb - 1;

//        printf("\n.B 4 ..\n");
//        for(int i=0; i < sb; i++){
//         printf ("b%d: %" PRIu64 "\n",i,  b[i]);
//        }


	/* Shift y so that the most significant digit of y is aligned with the
	 * most significant digit of x. */
	dv_lshd(b, b, sb + (n - t), (n - t));
//        printf("\n.B 5 ..\n");
//        for(int i=0; i < sb; i++){
//         printf ("b%d: %" PRIu64 "\n",i,  b[i]);
//        }


//	gmp_printf ("b %Mu\n", b[0]);
//        gmp_printf ("b %Mu\n", b[1]);
//        gmp_printf ("b %Mu\n", b[2]);
//        gmp_printf ("b %Mu\n", b[3]);
//        gmp_printf ("b %Mu\n", b[4]);
//        gmp_printf ("b %Mu\n", b[5]);
//        printf("\n....................... \n");

	/* Find the most significant digit of the quotient. */
//        printf("Let us enter the loop...\n");
	while (dv_cmp(a, b, sa) != RLC_LT) {
		c[n - t]++;
//                printf("arithmetic call...\n");
//                printf("%" PRIu64 "\n", c[n - t]);
		bn_subn_low(a, a, b, sa);
	}

//        printf("\n.B 6 ..\n");
//        for(int i=0; i < sb; i++){
//         printf ("b%d: %" PRIu64 "\n",i,  b[i]);
//        }

	/* Shift y back. */
	dv_rshd(b, b, sb + (n - t), (n - t));
//        printf("\n.B 7 ..\n");
//        for(int i=0; i < sb; i++){
//         printf ("b%d: %" PRIu64 "\n",i,  b[i]);
//        }


	/* Find the remaining digits. */
//        printf("limits: %d %d ", n, t+1);
	for (i = n; i >= (t + 1); i--) {
//        printf("t equlas: %d \n", t);
		dig_t tmp;

		if (i > sa) {
			continue;
		}

		if (a[i] == b[t]) {
			c[i - t - 1] = RLC_MASK(RLC_DIG);
		} else {
			RLC_DIV_DIG(c[i - t - 1], tmp, a[i], a[i - 1], b[t]);
		}
//        printf("\n.B 8 ..\n");
//        for(int i=0; i < sb; i++){
//         printf ("b%d: %" PRIu64 "\n",i,  b[i]);
//        }

		c[i - t - 1]++;
		do {
			c[i - t - 1]--;
			t1[0] = (t - 1 < 0) ? 0 : b[t - 1];
			t1[1] = b[t];

			carry = bn_mul1_low(t1, t1, c[i - t - 1], 2);
			t1[2] = carry;

			t2[0] = (i - 2 < 0) ? 0 : a[i - 2];
			t2[1] = (i - 1 < 0) ? 0 : a[i - 1];
			t2[2] = a[i];
		} while (dv_cmp(t1, t2, 3) == RLC_GT);
//        printf("\n.B 9 ..\n");
//        for(int i=0; i < sb; i++){
//         printf ("b%d: %" PRIu64 "\n",i,  b[i]);
//        }


		carry = bn_mul1_low(d, b, c[i - t - 1], sb);
		sd = sb;
		if (carry) {
			d[sd++] = carry;
		}

		carry = bn_subn_low(a + (i - t - 1), a + (i - t - 1), d, sd);
		sd += (i - t - 1);
		if (sa - sd > 0) {
			carry = bn_sub1_low(a + sd, a + sd, carry, sa - sd);
		}

//        printf("\n.B 10 ..\n");
//        for(int i=0; i < sb; i++){
//         printf ("b%d: %" PRIu64 "\n",i,  b[i]);
//        }

		if (carry) {
			sd = sb + (i - t - 1);
			carry = bn_addn_low(a + (i - t - 1), a + (i - t - 1), b, sb);
			carry = bn_add1_low(a + sd, a + sd, carry, sa - sd);
			c[i - t - 1]--;
		}
	}
	/* Remainder should be not be longer than the divisor. */
//        printf("\n.B 11 ..\n");
//        for(int i=0; i < sb; i++){
//         printf ("b%d: %" PRIu64 "\n",i,  b[i]);
//        }

	bn_rshb_low(d, a, sb, norm);

}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_sub_dig(bn_t c, const bn_t a, dig_t b) {
        dig_t carry;

                bn_grow(c, a->used);

                /* If a < 0, compute c = -(|a| + b). */
                if (a->sign == RLC_NEG) {
                        carry = bn_add1_low(c->dp, a->dp, b, a->used);
                        if (carry) {
                                bn_grow(c, a->used + 1);
                                c->dp[a->used] = carry;
                        }
                        c->used = a->used + carry;
                        c->sign = RLC_NEG; 
                } else {
                        /* If a > 0 && |a| >= b, compute c = (|a| - b). */
                        if (a->used > 1 || a->dp[0] >= b) {
                                carry = bn_sub1_low(c->dp, a->dp, b, a->used);
                                c->used = a->used;
                                c->sign = RLC_POS;
                        } else {
                                /* If a > 0 && a < b. */
                                if (a->used == 1) {
                                        c->dp[0] = b - a->dp[0];
                                } else {
                                        c->dp[0] = b;
                                }
                                c->used = 1;
                                c->sign = RLC_NEG;
                        }
                }
                bn_trim(c);
}

/**
 * Divides two multiple precision integers, computing the quotient and the
 * remainder.
 *
 * @param[out] c                - the quotient.
 * @param[out] d                - the remainder.
 * @param[in] a                 - the dividend.
 * @param[in] b                 - the the divisor.
 */
__device__
#if INLINE == 0
__noinline__
#endif
void bn_div_imp(bn_t c, bn_t d, const bn_t a, const bn_t b) {
        bn_t q, x, y, r;
        int sign;

// printf("1. bn_div_imp");
        x = (bn_t) malloc(sizeof(bn_st));
// printf("2. bn_div_imp");
        x->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
// printf("3. bn_div_imp");
        x->alloc = RLC_BN_SIZE;
// printf("4. bn_div_imp");
        x->sign = RLC_POS;

        q = (bn_t) malloc(sizeof(bn_st));
// printf("5. bn_div_imp");
        q->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
// printf("6. bn_div_imp");
        q->alloc = RLC_BN_SIZE;
// printf("7. bn_div_imp");
        y = (bn_t) malloc(sizeof(bn_st));
// printf("8. bn_div_imp");
        y->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
// printf("9. bn_div_imp");
        y->alloc = RLC_BN_SIZE;
// printf("10. bn_div_imp");
        y->sign = RLC_POS;

        r = (bn_t) malloc(sizeof(bn_st));
// printf("11. bn_div_imp");
        r->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
// printf("12. bn_div_imp");
        r->alloc = RLC_BN_SIZE;
// printf("13. bn_div_imp");
        r->sign = RLC_POS;

        bn_new(x);
        bn_new(q);
        bn_new(y);
        bn_new(r);

//        printf("a-> used %d ....\n", a->used);
//        printf("b-> used %d ....\n", b->used);

//	printf ("a1: %" PRIu64 "\n", a->dp[0]);
//	printf ("a2: %" PRIu64 "\n", a->dp[1]);
//	printf ("a3: %" PRIu64 "\n", a->dp[2]);
//	printf ("a4: %" PRIu64 "\n", a->dp[3]);
//	printf ("a5: %" PRIu64 "\n", a->dp[4]);
//	printf ("a6: %" PRIu64 "\n", a->dp[5]);
//        printf("\n....................... \n");
//        printf("\n....................... \n");
//        printf("\n....................... \n");
//	printf ("b1: %" PRIu64 "\n", b->dp[0]);
//	printf ("b2: %" PRIu64 "\n", b->dp[1]);
//	printf ("b3: %" PRIu64 "\n", b->dp[2]);
//	printf ("b4: %" PRIu64 "\n", b->dp[3]);
//	printf ("b5: %" PRIu64 "\n", b->dp[4]);
//	printf ("b6: %" PRIu64 "\n", b->dp[5]);

        /* If |a| < |b|, we're done. */
// printf("14. bn_div_imp");
        if (bn_cmp_abs(a, b) == RLC_LT) {

//        printf("bn_cmp_abs(a, b) == RLC_LT...\n");
//        printf("a->sign: %d\n", a->sign);
//        printf("b->sign: %d\n", b->sign);

                if (bn_sign(a) == bn_sign(b)) {
//// printf("15. bn_div_imp");
                        if (c != NULL) {
//                        printf("bn_zero ...\n");
                                bn_zero(c);
                        }
                        if (d != NULL) {
                                bn_copy(d, a);
                        }
                } else {
// printf("16. bn_div_imp");
                        if (c != NULL) {
                                bn_set_dig(c, 1);
                                bn_neg(c, c);
                        }
                        if (d != NULL) {
                                bn_add(d, a, b);
                        }
                }
//                printf("Returning from function call...");
                return;
        }

                /* Be conservative about space for scratch memory, many attempts to
                 * optimize these had invalid reads. */
// printf("17. bn_div_imp");

                bn_new_size(x, a->used + 1);
// printf("18. bn_div_imp");
                bn_new_size(q, a->used + 1);
                bn_new_size(y, a->used + 1);
                bn_new_size(r, a->used + 1);

                bn_zero(q);
                bn_zero(r);
// printf("19. bn_div_imp");
                bn_abs(x, a);
                bn_abs(y, b);

//                printf("calling bn_divn_low...\n");

                /* Find the sign. */
                sign = (a->sign == b->sign ? RLC_POS : RLC_NEG);

// printf("20. bn_div_imp");
                bn_divn_low(q->dp, r->dp, x->dp, a->used, y->dp, b->used);
// printf("21. bn_div_imp");


                q->used = a->used - b->used + 1;
                q->sign = sign;
                bn_trim(q);

                r->used = b->used;
                r->sign = b->sign;
                bn_trim(r);

                /* We have the quotient in q and the remainder in r. */
                if (c != NULL) {
                        if ((bn_is_zero(r)) || (bn_sign(a) == bn_sign(b))) {
                                bn_copy(c, q);
                        } else {
                                bn_sub_dig(c, q, 1);
                        }
                }

                if (d != NULL) {
                        if ((bn_is_zero(r)) || (bn_sign(a) == bn_sign(b))) {
                                bn_copy(d, r);
                        } else {
                                bn_sub(d, b, r);
                        }
                }
//       printf("leaving bn_div_imp...\n");
//        printf("\n....................... \n");
//	printf ("d1: %" PRIu64 "\n", d->dp[0]);
//	printf ("d2: %" PRIu64 "\n", d->dp[1]);
//	printf ("d3: %" PRIu64 "\n", d->dp[2]);
//	printf ("d4: %" PRIu64 "\n", d->dp[3]);
//	printf ("d5: %" PRIu64 "\n", d->dp[4]);
//	printf ("d6: %" PRIu64 "\n", d->dp[5]);
        free(q->dp);
        free(q);
        free(y->dp);
        free(y);
        free(r->dp);
        free(r);
        free(x->dp);
        free(x);
}


__device__
#if INLINE == 0
__noinline__
#endif
void bn_div_rem(bn_t c, bn_t d, const bn_t a, const bn_t b) {
 if (bn_is_zero(b)) {
  printf("bn_div_rem zero!!!...\n");
  return;
 }
 bn_div_imp(c, d, a, b);
}

__device__
#if INLINE == 0
__noinline__
#endif
void bn_mod_basic(bn_t c, const bn_t a, const bn_t m) {
        bn_div_rem(NULL, c, a, m);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_add_basic(fp_t c, const fp_t a, const fp_t b) {
        dig_t carry;

        carry = fp_addn_low(c, a, b);
        if (carry || (dv_cmp(c, shared_prime, RLC_FP_DIGS) != RLC_LT)) {
                carry = fp_subn_low(c, c, shared_prime);
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t fp_mul1_low(dig_t *c, const dig_t *a, dig_t digit) {
        dig_t r0, r1, carry = 0;
        for (int i = 0; i < RLC_FP_DIGS; i++, a++, c++) {
                RLC_MUL_DIG(r1, r0, *a, digit);
                *c = r0 + carry;
                carry = r1 + (*c < carry);
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_zero(fp_t a) {
        dv_zero(a, RLC_FP_DIGS);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_copy(fp_t c, const fp_t a) {

//    printf("fp_copy... RLC_FP_DIGS: %d \n", RLC_FP_DIGS);
//  if( c == NULL){
//    printf("c has problems.... \n");
//   }
//   else{
//    printf("c is OK .... \n");
//   } 
//
//  if( a == NULL){
//    printf("a has problems.... \n");
//   }
//   else{
//    printf("a is OK .... \n");
//   } 
        dv_copy(c, a, RLC_FP_DIGS);
}    
__device__
#if INLINE == 0
__noinline__
#endif
void fp_rdc_basic(fp_t c, dv_t a) {
        dv_t t0, t1, t2, t3;

        t0 = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
        t1 = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
        t2 = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
        t3 = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));

//   printf("RLC_DV_DIGS %d , RLC_FP_DIGS %d inside fp_rdc_basic...\n",RLC_DV_DIGS, RLC_FP_DIGS );

//  printf("a in fp_rdc_basic: \n ");
//  printf("%" PRIu64 "\n", *a);

        dv_copy(t2, a, 2 * RLC_FP_DIGS);
//  printf("t2 in fp_rdc_basic: \n ");
//  printf("%" PRIu64 "\n", *t2);
        dv_copy(t3, shared_prime, RLC_FP_DIGS);

//  printf("t3 in fp_rdc_basic: \n ");
//  printf("%" PRIu64 "\n", *t3);
//  printf("t2 in fp_rdc_basic: \n ");
//  printf("%" PRIu64 "\n", *t2);
// itt a t/knek tul kicsi hely van foglalva es tul fogjak cimezni egymast....

        bn_divn_low(t0, t1, t2, 2 * RLC_FP_DIGS, t3, RLC_FP_DIGS);

//  printf("t0 in fp_rdc_basic: \n ");
//  printf("%" PRIu64 "\n", *t0);
//  printf("t1 in fp_rdc_basic: \n ");
//  printf("%" PRIu64 "\n", *t1);
        fp_copy(c, t1);
//  printf("c in fp_rdc_basic: \n ");
//  printf("%" PRIu64 "\n", *c);
//        printf("leaving fp_rdc_basic...\n");
        free(t0);
        free(t1);
        free(t2);
        free(t3);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_prime_conv_dig(fp_t c, dig_t a) {
// dv_t t;
// t = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));

//        ctx_t *ctx = core_get();
//        bn_null(t);
//        dv_new(t);
//// #if FP_RDC == MONTY
//        if (a != 1) {
//         dv_zero(t, 2 * RLC_FP_DIGS + 1);
//         t[RLC_FP_DIGS] = fp_mul1_low(t, shared_conv, a);
//         fp_rdc_basic(c, t);
//        } else {
//         dv_copy(c, shared_one, RLC_FP_DIGS);
//        }
//// #else
//         (void)ctx;
         fp_zero(c);
         c[0] = a;
// #endif
// free(t);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp_set_dig(fp_t c, dig_t a) {
        fp_prime_conv_dig(c, a);
}    
__device__
#if INLINE == 0
__noinline__
#endif
int bn_bits(const bn_t a) {
        int bits;

        if (bn_is_zero(a)) {
                return 0;
        }

        /* Bits in lower digits. */
        bits = (a->used - 1) * RLC_DIG;

        return bits + util_bits_dig(a->dp[a->used - 1]);
}
__device__
#if INLINE == 0
__noinline__
#endif

dig_t bn_sqra_low(dig_t *c, const dig_t *a, int size) {
	int i;
	dig_t t, c0, c1;

	t = a[0];

	dig_t r0, r1, _r0, _r1, s0, s1, t0, t1;
	/* Accumulate this column with the square of a->dp[i]. */
	RLC_MUL_DIG(_r1, _r0, t, t);
	r0 = _r0 + c[0];
	r1 = _r1 + (r0 < _r0);
	c[0] = r0;

	/* Update the carry. */
	c0 = r1;
	c1 = 0;

	/* Version of the main loop not using double-precision types. */
	for (i = 1; i < size; i++) {
		RLC_MUL_DIG(_r1, _r0, t, a[i]);
		r0 = _r0 + _r0;
		r1 = _r1 + _r1 + (r0 < _r0);

		s0 = r0 + c0;
		s1 = r1 + (s0 < r0);

		t0 = s0 + c[i];
		t1 = s1 + (t0 < s0);
		c[i] = t0;

		/* Accumulate the old delayed carry. */
		c0 = t1 + c1;
		/* Compute the new delayed carry. */
		c1 = (t1 < s1) || (s1 < r1) || (r1 < _r1) || (c0 < c1);
	}

	c[size] += c0;
	c1 += (c[size] < c0);
	return c1;
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_sqr_basic(fp_t c, const fp_t a) {
        int i;
        dv_t t;

        t = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
//  printf("entering  fp_sqr_basic \n");
//  printf("(RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t): %d\n",(RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
//
//  printf("RLC_DV_DIGS  %d\n",RLC_DV_DIGS );
//  printf("FP_PRIME  %d\n",FP_PRIME );
//  printf("RLC_FP_DIGS  %d\n",RLC_FP_DIGS );
//  printf("RLC_DIG  %d\n",RLC_DIG );
//  printf("RLC_BN_SIZE  %d\n",RLC_BN_SIZE );


//  printf("a in fp_sqr_basic: \n ");
//  printf("%" PRIu64 "\n", *a);
//        dv_null(t);
//        dv_new(t);
        dv_zero(t, 2 * RLC_FP_DIGS);
//  printf("t in fp_sqr_basic: \n ");
//  printf("%" PRIu64 "\n", *t);
        for (i = 0; i < RLC_FP_DIGS - 1; i++) {
                t[RLC_FP_DIGS + i + 1] =
                                bn_sqra_low(t + 2 * i, a + i, RLC_FP_DIGS - i);
        }
//  printf("2. t in fp_sqr_basic: \n ");
//  printf("%" PRIu64 "\n", *t);
        bn_sqra_low(t + 2 * i, a + i, 1);
//  printf("3. t in fp_sqr_basic: \n ");
//  printf("%" PRIu64 "\n", *t);
//  printf("calling fp_rdc_basic... \n ");
        fp_rdc_basic(c, t);
//  printf("4. c in fp_sqr_basic: \n ");
//  printf("%" PRIu64 "\n", *c);
        free(t);
//        printf("leaving  fp_sqr_basic \n");
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_sqr(fp_t c, const fp_t a) {
  fp_sqr_basic(c,a);
}
__device__
#if INLINE == 0
__noinline__
#endif
int bn_get_bit(const bn_t a, int bit) {
        int d;
        
        if (bit < 0) {
                printf("bn_get_bit error...\n");
                return 0;
        }

        if (bit > bn_bits(a)) {
                return 0;
        }

        RLC_RIP(bit, d, bit);

        if (d >= a->used) {
                return 0;
        } else {
                return (a->dp[d] >> bit) & (dig_t)1;
        }
}  
__device__
#if INLINE == 0
__noinline__
#endif
dig_t fp_mula_low(dig_t *c, const dig_t *a, dig_t digit) {
        dig_t _c, r0, r1, carry = 0;
        for (int i = 0; i < RLC_FP_DIGS; i++, a++, c++) {
                /* Multiply the digit *a by d and accumulate with the previous
                 * result in the same columns and the propagated carry. */
                RLC_MUL_DIG(r1, r0, *a, digit);
//                printf("%d. : %" PRIu64 "\n",i, *a);
                _c = r0 + carry;
                carry = r1 + (_c < carry);
                /* Increment the column and assign the result. */
                *c = *c + _c;
                /* Update the carry. */
                carry += (*c < _c);
        }
//        printf("returning carry: %" PRIu64 "\n", carry);
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_mul_basic(fp_t c, const fp_t a, const fp_t b) {
        int i;
        dv_t t;
        dig_t carry;

//        dv_null(t);
        /* We need a temporary variable so that c can be a or b. */
//        dv_new(t);
        t = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));

        dv_zero(t, 2 * RLC_FP_DIGS);
        for (i = 0; i < RLC_FP_DIGS; i++) {
                carry = fp_mula_low(t + i, b, *(a + i));
                *(t + i + RLC_FP_DIGS) = carry;
        }
//        printf("result in fp_mul_basic: ");
//        printf("%" PRIu64 "\n", *t);
        fp_rdc_basic(c, t);
//        printf("CCCCC result in fp_mul_basic: ");
//        printf("%" PRIu64 "\n", *c);
        free(t);
}
__device__
#if INLINE == 0
__noinline__
#endif
int fp_is_zero(const fp_t a) {
        int i;
        dig_t t = 0;

//        printf("fp_is_zero called, now iside...\n");

        for (i = 0; i < RLC_FP_DIGS; i++) {
                t |= a[i];
        }
//        printf("leaving function fp_is_zero.\n");
        return !t;
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_prime_back(bn_t c, const fp_t a) {
        dv_t t;

        t = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));

        int i;
                bn_grow(c, RLC_FP_DIGS);
                for (i = 0; i < RLC_FP_DIGS; i++) {
                        c->dp[i] = a[i];
                }

#if FP_RDC == MONTY
                dv_zero(t, 2 * RLC_FP_DIGS + 1);
                dv_copy(t, a, RLC_FP_DIGS);
                fp_rdc_basic(c->dp, t);
#endif

                c->used = RLC_FP_DIGS;
                c->sign = RLC_POS;
                bn_trim(c);
                free(t);
}
__device__
#if INLINE == 0
__noinline__
#endif
int bn_cmp_dig(const bn_t a, dig_t b) {
        if (a->sign == RLC_NEG) {
                return RLC_LT;
        }

        if (a->used > 1) {
                return RLC_GT;
        }

        if (a->dp[0] > b) {
                return RLC_GT;
        }

        if (a->dp[0] < b) {
                return RLC_LT;
        }

        return RLC_EQ;
}

__device__
#if INLINE == 0
__noinline__
#endif
dig_t bn_mula_low(dig_t *c, const dig_t *a, dig_t digit, int size) {
        dig_t _c, r0, r1, carry = 0;
        for (int i = 0; i < size; i++, a++, c++) {
                /* Multiply the digit *a by d and accumulate with the previous
                 * result in the same columns and the propagated carry. */
                RLC_MUL_DIG(r1, r0, *a, digit);
                _c = r0 + carry;
                carry = r1 + (_c < carry);
                /* Increment the column and assign the result. */
                *c = *c + _c;
                /* Update the carry. */
                carry += (*c < _c);
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_mul_basic(bn_t c, const bn_t a, const bn_t b) {
        int i;
        bn_t t;

        t  = (bn_t ) malloc(sizeof(bn_st));
        t->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
        t->alloc = RLC_BN_SIZE;
        t->sign = RLC_POS;


        dig_t carry;

                /* We need a temporary variable so that c can be a or b. */
                bn_new_size(t, a->used + b->used);
                bn_zero(t);
                t->used = a->used + b->used;

                for (i = 0; i < a->used; i++) {
                        carry = bn_mula_low(t->dp + i, b->dp, *(a->dp + i), b->used);
                        *(t->dp + i + b->used) = carry;
                }
                t->sign = a->sign ^ b->sign;
                bn_trim(t);

                /* Swap c and t. */
                bn_copy(c, t);
 free(t);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_mul(fp_t c, const fp_t a, const fp_t b) {
 fp_mul_basic(c, a, b);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_prime_conv(fp_t c, const bn_t a) {
 bn_t t; 
 t  = (bn_t ) malloc(sizeof(bn_st));
 t->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 t->alloc = RLC_BN_SIZE;
 t->sign = RLC_POS;

// printf("RLC_BN_SIZE: %d \n ", RLC_BN_SIZE);
// printf("RLC_FP_DIGS: %d \n ", RLC_FP_DIGS);

// printf("input operand a \n ");
// for(int i=0; i < a->used; i++){
//  printf("%" PRIu64 "\n", a->dp[i]);
// }
 /* Reduce a modulo the prime to ensure bounds. */

//                printf("\n printing in fp_prime_conv.... \n");
//                for(int i=0; i < a->used; i++){
//                 printf("a %d %" PRIu64 " \n",i, a->dp[i]);
//                }
 bn_mod_basic(t, a, shared_prime_bn);
//                for(int i=0; i < t->used; i++){
//                 printf("t %d %" PRIu64 " \n",i, t->dp[i]);
//                }
//


 if (bn_is_zero(t)) {
  fp_zero(c);
 } 
 else {
  /* Copy used digits, fill the rest with zero. */
//  printf("t->used: %d \n", t->used);
//  printf("fp_prime_conv printing \n ");
//  for(int i=0; i < t->used; i++){
//   printf("%" PRIu64 "\n", t->dp[i]);
//  }
  dv_copy(c, t->dp, t->used);
  dv_zero(c + t->used, RLC_FP_DIGS - t->used);
// Ezt itt tilos visszakommentezni ha nem MONTY aritmetika van...
//#if FP_RDC == MONTY
//  printf("FP_RDC == MONTY \n ");
// TODO is this ok?
//  printf("Printing c before Montgomery reduction... \n");
//  for(int i=0; i < t->used; i++){
//    printf("c%d %" PRIu64 "\n",i, c[i]);
//  }

//  fp_mul(c, c, &shared_conv[0]);
//
//  printf("Printing c after Montgomery reduction... \n");
//  printf("%" PRIu64 "\n", shared_conv[0]);
//  printf("%" PRIu64 "\n", shared_conv[1]);
//  printf("%" PRIu64 "\n", shared_conv[2]);
//  printf("%" PRIu64 "\n", shared_conv[3]);
//  printf("%" PRIu64 "\n", shared_conv[4]);
//  printf("%" PRIu64 "\n", shared_conv[5]);
//#endif
 }
 free(t->dp);
 free(t);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_inv_exgcd(fp_t c, const fp_t a) {
 bn_t u, v, g1, g2, p, q, r;
 
 u  = (bn_t ) malloc(sizeof(bn_st));
 u->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 u->alloc = RLC_BN_SIZE;
 u->sign = RLC_POS;
 u->used = 1;

 v  = (bn_t ) malloc(sizeof(bn_st));
 v->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 v->alloc = RLC_BN_SIZE;
 v->sign = RLC_POS;
 v->used = 1;

 g1  = (bn_t ) malloc(sizeof(bn_st));
 g1->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 g1->alloc = RLC_BN_SIZE;
 g1->sign = RLC_POS;
 g1->used = 1;

 g2  = (bn_t ) malloc(sizeof(bn_st));
 g2->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 g2->alloc = RLC_BN_SIZE;
 g2->sign = RLC_POS;
 g2->used = 1;

 p  = (bn_t ) malloc(sizeof(bn_st));
 p->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 p->alloc = RLC_BN_SIZE;
 p->sign = RLC_POS;
 p->used = 1;

 q  = (bn_t ) malloc(sizeof(bn_st));
 q->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 q->alloc = RLC_BN_SIZE;
 q->sign = RLC_POS;
 q->used = 1;

 r  = (bn_t ) malloc(sizeof(bn_st));
 r->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 r->alloc = RLC_BN_SIZE;
 r->sign = RLC_POS;
 r->used = 1;

// printf("fp_inv_exgcd called ...\n");
 if (fp_is_zero(a)) {
  printf("fp_is_zero in fp_inv_exgcd...\n");
  return;
 }
 /* u = a, v = p, g1 = 1, g2 = 0. */

       printf("1. a ... \n");
       printf ("a0 %" PRIu64 "\n", *(a) );
       printf ("a1 %" PRIu64 "\n", *(a + 1) );
       printf ("a2 %" PRIu64 "\n", *(a + 2) );
       printf ("a3 %" PRIu64 "\n", *(a + 3) );
       printf ("a4 %" PRIu64 "\n", *(a + 4) );
       printf ("a5 %" PRIu64 "\n", *(a + 5) );

 fp_prime_back(u, a);

       printf("2. u ... \n");
       printf ("u0 %" PRIu64 "\n", *(u->dp) );
       printf ("u1 %" PRIu64 "\n", *(u->dp + 1) );
       printf ("u2 %" PRIu64 "\n", *(u->dp + 2) );
       printf ("u3 %" PRIu64 "\n", *(u->dp + 3) );
       printf ("u4 %" PRIu64 "\n", *(u->dp + 4) );
       printf ("u5 %" PRIu64 "\n", *(u->dp + 5) );

 p->used = RLC_FP_DIGS;
 dv_copy(p->dp, shared_prime, RLC_FP_DIGS);
       printf("3. p ... \n");
       printf ("p0 %" PRIu64 "\n", *(p->dp) );
       printf ("p1 %" PRIu64 "\n", *(p->dp + 1) );
       printf ("p2 %" PRIu64 "\n", *(p->dp + 2) );
       printf ("p3 %" PRIu64 "\n", *(p->dp + 3) );
       printf ("p4 %" PRIu64 "\n", *(p->dp + 4) );
       printf ("p5 %" PRIu64 "\n", *(p->dp + 5) );
 bn_copy(v, p);
 bn_set_dig(g1, 1);
 bn_zero(g2);
 /* While (u != 1. */
 while (bn_cmp_dig(u, 1) != RLC_EQ) {
  /* q = [v/u], r = v mod u. */
  bn_div_rem(q, r, v, u);
       printf("4. r ... \n");
       printf ("r0 %" PRIu64 "\n", *(r->dp) );
       printf ("r1 %" PRIu64 "\n", *(r->dp + 1) );
       printf ("r2 %" PRIu64 "\n", *(r->dp + 2) );
       printf ("r3 %" PRIu64 "\n", *(r->dp + 3) );
       printf ("r4 %" PRIu64 "\n", *(r->dp + 4) );
       printf ("r5 %" PRIu64 "\n", *(r->dp + 5) );

       printf("5. q ... \n");
       printf ("q0 %" PRIu64 "\n", *(q->dp) );
       printf ("q1 %" PRIu64 "\n", *(q->dp + 1) );
       printf ("q2 %" PRIu64 "\n", *(q->dp + 2) );
       printf ("q3 %" PRIu64 "\n", *(q->dp + 3) );
       printf ("q4 %" PRIu64 "\n", *(q->dp + 4) );
       printf ("q5 %" PRIu64 "\n", *(q->dp + 5) );
  /* v = u, u = r. */
  bn_copy(v, u);
  bn_copy(u, r);
  /* r = g2 - q * g1. */
  bn_mul_basic(r, q, g1);
       printf("6. r ... \n");
       printf ("r0 %" PRIu64 "\n", *(r->dp) );
       printf ("r1 %" PRIu64 "\n", *(r->dp + 1) );
       printf ("r2 %" PRIu64 "\n", *(r->dp + 2) );
       printf ("r3 %" PRIu64 "\n", *(r->dp + 3) );
       printf ("r4 %" PRIu64 "\n", *(r->dp + 4) );
       printf ("r5 %" PRIu64 "\n", *(r->dp + 5) );
  bn_sub(r, g2, r);
  /* g2 = g1, g1 = r. */
  bn_copy(g2, g1);
  bn_copy(g1, r);
 }
 if (bn_sign(g1) == RLC_NEG) {
  bn_add(g1, g1, p);
 }
 fp_prime_conv(c, g1);
       printf("7. c ... \n");
       printf ("c0 %" PRIu64 "\n", *(c) );
       printf ("c1 %" PRIu64 "\n", *(c + 1) );
       printf ("c2 %" PRIu64 "\n", *(c + 2) );
       printf ("c3 %" PRIu64 "\n", *(c + 3) );
       printf ("c4 %" PRIu64 "\n", *(c + 4) );
       printf ("c5 %" PRIu64 "\n", *(c + 5) );

 free(g1->dp);
 free(g2->dp);
 free(u->dp);
 free(v->dp);
 free(p->dp);
 free(q->dp);
 free(r->dp);

 free(u);
 free(v);
 free(g1);
 free(g2);
 free(p);
 free(q);
 free(r);

}
// Exponentiates a prime field element. Computes C = A^B (mod p).
__device__
#if INLINE == 0
__noinline__
#endif
void fp_exp_basic(fp_t c, const fp_t a, const bn_t b) {
        int i, l;

//  printf("fp_exp_basic a: \n");
//  print_multiple_precision(a,6);
//  print_line();
//
//  printf("fp_exp_basic b: \n");
//  print_multiple_precision(b->dp,6);
//  print_line();

//  printf("inside fp_exp_basic...\n");
//  printf("a: \n ");
//  printf("%" PRIu64 "\n", *a);
//  printf("b: \n ");
//  printf("%" PRIu64 "\n", b->dp[0]);
// printf("1. fp_exp_basic // ");
        fp_t r;
        r = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        if(r == NULL){
         printf("r has problems...\n");
        }
        if (bn_is_zero(b)) {
         fp_set_dig(c, 1);
         return;
        }
//        fp_new(r);
        l = bn_bits(b);
        fp_copy(r, a);
        if(r == NULL){
         printf("r has problems...\n");
        }
//  printf("l: %d \n ", l);

//  printf("first r: \n ");
//  printf("%" PRIu64 "\n", *r);

        for (i = l - 2; i >= 0; i--) {
// printf("9. fp_exp_basic // ");
//         printf("1. %d. r %" PRIu64 "\n",i, *r);


         fp_sqr_basic(r, r);
//         printf("2. %d. r %" PRIu64 "\n",i, *r);
//  printf("%d r: \n ", i);
//  printf("%" PRIu64 "\n", *r);

        if(r == NULL){
         printf("r has problems...\n");
        }
// printf("10. fp_exp_basic // ");
// printf("%" PRIu64 "\n", *r);
         if (bn_get_bit(b, i)) {
          fp_mul_basic(r, r, a);
//  printf("fp_mul_basic r: \n ", i);
//  printf("%" PRIu64 "\n", *r);
         }
        }
        if(r == NULL){
         printf("r has problems...\n");
        }
        if (bn_sign(b) == RLC_NEG) {
         fp_inv_exgcd(c, r);
        } else {
// printf("15. fp_exp_basic // ");
        if(r == NULL){
         printf("r has problems...\n");
        }
         fp_copy(c, r);
        }

        free(r);
//  printf("fp_exp_basic c: \n");
//  print_multiple_precision(c,6);
//  print_line();
// printf("16. fp_exp_basic // ");
//  printf("c: \n ");
//  printf("%" PRIu64 "\n", *c);
// printf("leaving fp_exp_basic...\n");
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_inv_basic(fp_t c, const fp_t a) {
        bn_t e;
        e  = (bn_t ) malloc(sizeof(bn_st));
        e->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
        e->alloc = RLC_BN_SIZE;
        e->sign = RLC_POS;

//        bn_null(e);
        if (fp_is_zero(a)) {
                printf("fp_is_zero in fp_inv_basic...\n");
                return;
        }
//                bn_new(e);
        e->used = RLC_FP_DIGS;
        dv_copy(e->dp, shared_prime, RLC_FP_DIGS);
        bn_sub_dig(e, e, 2);
        fp_exp_basic(c, a, e);
        free(e);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_addm_low(dig_t *c, const dig_t *a, const dig_t *b) {
        int i;
        dig_t carry, c0, c1, r0, r1;

        carry = 0;
//        printf("calling fp_addm_low...\n");
//        printf("RLC_FP_DIGS %d ...\n", RLC_FP_DIGS);
        for (i = 0; i < RLC_FP_DIGS; i++, a++, b++) {
                r0 = (*a) + (*b);
                c0 = (r0 < (*a));
                r1 = r0 + carry;
                c1 = (r1 < r0);
                carry = c0 | c1;
                c[i] = r1;
        }
        if (carry || (dv_cmp(c, shared_prime, RLC_FP_DIGS) != RLC_LT)) {
                carry = fp_subn_low(c, c, shared_prime);
        }
//        printf("returning from fp_addm_low...\n");
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_add(fp_t c, const fp_t a, const fp_t b) {
        fp_addm_low(c, a, b);
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t fp_prime_get_mod8(){
 return 3;
}
__device__
#if INLINE == 0
__noinline__
#endif
int fp_prime_get_qnr(){
 return -1;
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_dblm_low(dig_t *c, const dig_t *a) {
        int i;
        dig_t carry, c0, c1, r0, r1;

        carry = 0;
        for (i = 0; i < RLC_FP_DIGS; i++, a++) {
                r0 = (*a) + (*a);
                c0 = (r0 < (*a));
                r1 = r0 + carry;
                c1 = (r1 < r0);
                carry = c0 | c1;
                c[i] = r1;
        }
        if (carry || (dv_cmp(c, shared_prime, RLC_FP_DIGS) != RLC_LT)) {
                carry = fp_subn_low(c, c, shared_prime);
        }
}       

__device__
#if INLINE == 0
__noinline__
#endif
void fp_dbl(fp_t c, const fp_t a) {
        fp_dblm_low(c, a);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_sqr_basic(fp2_t c, fp2_t a) {
 fp_t t0, t1, t2;

// printf("fp2_sqr_basic a: %" PRIu64 "\n", *a[0]);
// printf("fp2_sqr_basic a: %" PRIu64 "\n", *a[1]);

 t0 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
 t1 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
 t2 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));

 /* t0 = (a_0 + a_1). */
 fp_add(t0, a[0], a[1]);
 /* t1 = (a_0 - a_1). */
 fp_sub(t1, a[0], a[1]);
 /* t1 = a_0 + u^2 * a_1. */
 for (int i = -1; i > fp_prime_get_qnr(); i--) {
  fp_sub(t1, t1, a[1]);
 }
 for (int i = 1; i < fp_prime_get_qnr(); i++) {
  fp_add(t1, t1, a[1]);
 }
 if (fp_prime_get_qnr() == -1) {
  /* t2 = 2 * a_0. */
  fp_dbl(t2, a[0]);
  /* c_1 = 2 * a_0 * a_1. */
  fp_mul(c[1], t2, a[1]);
  /* c_0 = a_0^2 + a_1^2 * u^2. */
  fp_mul(c[0], t0, t1);
 } else {
 /* c_1 = a_0 * a_1. */
  fp_mul(c[1], a[0], a[1]);
 /* c_0 = a_0^2 + a_1^2 * u^2. */
  fp_mul(c[0], t0, t1);
 for (int i = -1; i > fp_prime_get_qnr(); i--) {
  fp_add(c[0], c[0], c[1]);
 }
 for (int i = 1; i < fp_prime_get_qnr(); i++) {
  fp_add(c[0], c[0], c[1]);
 }
 /* c_1 = 2 * a_0 * a_1. */
  fp_dbl(c[1], c[1]);
 }
 /* c = c_0 + c_1 * u. */
 free(t0);
 free(t1);
 free(t2);
// printf("fp2_sqr_basic  RESULTS c: %" PRIu64 "\n", *c[0]);
// printf("fp2_sqr_basic  RESULTS c: %" PRIu64 "\n", *c[1]);

}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t fp_addd_low(dig_t *c, const dig_t *a, const dig_t *b) {
        int i;
        dig_t carry, c0, c1, r0, r1;

        carry = 0;
        for (i = 0; i < 2 * RLC_FP_DIGS; i++, a++, b++) {
                r0 = (*a) + (*b);
                c0 = (r0 < (*a));
                r1 = r0 + carry;
                c1 = (r1 < r0);
                carry = c0 | c1;
                c[i] = r1;
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_addc_low(dig_t *c, const dig_t *a, const dig_t *b) {
        dig_t carry = fp_addd_low(c, a, b);

        if (carry || (dv_cmp(c + RLC_FP_DIGS, shared_prime, RLC_FP_DIGS) != RLC_LT)) {
                carry = fp_subn_low(c + RLC_FP_DIGS, c + RLC_FP_DIGS, shared_prime);
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_subc_low(dig_t *c, const dig_t *a, const dig_t *b) {
        int i;
        dig_t carry, r0, diff;

        /* Zero the carry. */
        carry = 0;
        for (i = 0; i < 2 * RLC_FP_DIGS; i++, a++, b++) {
                diff = (*a) - (*b);
                r0 = diff - carry;
                carry = ((*a) < (*b)) || (carry && !diff);
                c[i] = r0;
        }
        if (carry) {
                fp_addn_low(c + RLC_FP_DIGS, c + RLC_FP_DIGS, shared_prime);
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_rdc(fp_t c, dv_t a) {
        fp_rdc_basic(c, a);
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_read_raw(bn_t a, const dig_t *raw, int len) {
 bn_grow(a, len); 
 a->used = len;  
 a->sign = RLC_POS;
 dv_copy(a->dp, raw, len);
 bn_trim(a);
} 
//__device__
//#if INLINE == 0
//__noinline__
//#endif
//void util_print(const char *format, ...) {
//        va_list list;
//        va_start(list, format);
//        vprintf(format, list);
//        fflush(stdout);
//        va_end(list);
//}
__device__
#if INLINE == 0
__noinline__
#endif
void util_print_dig(dig_t a, int pad) {
if (pad) {
 printf("%.16" PRIX64, (uint64_t) a);
 } else {
 printf("%" PRIX64, (uint64_t) a);
}
///if (pad) {
/// util_print("%.16" PRIX64, (uint64_t) a);
/// } else {
/// util_print("%" PRIX64, (uint64_t) a);
///}
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_print(const fp_t a) {
        int i;
        bn_t t;


 t  = (bn_t ) malloc(sizeof(bn_st));
 t->dp = (dig_t* ) malloc(RLC_FP_DIGS * sizeof(dig_t));
 t->alloc = RLC_FP_DIGS;
 t->sign = RLC_POS;

//#if FP_RDC == MONTY
//                if (a != fp_prime_get()) {
//                        fp_prime_back(t, a);
//                } else {
//                        bn_read_raw(t, a, RLC_FP_DIGS);
//                }
//#else
                bn_read_raw(t, a, RLC_FP_DIGS);
//#endif

                for (i = RLC_FP_DIGS - 1; i > 0; i--) {
                        if (i >= t->used) {
                                util_print_dig(0, 1);
                        } else {
                                util_print_dig(t->dp[i], 1);
                        }
                        printf(" ");
                }
                util_print_dig(t->dp[0], 1);
                printf("\n");

// Ez lehet hogy majd okoz memóriaszivárgást...
//                bn_free(t);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_print(fp2_t a) {
        fp_print(a[0]);
        fp_print(a[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_mul_basic(fp2_t c, fp2_t a, fp2_t b) {
	dv_t t0, t1, t2, t3, t4;

        t0 = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
        t1 = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
        t2 = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
        t3 = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
        t4 = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
//        printf("now in fp2_mul_basic... \n");
//        fp2_print(c);
//        fp2_print(a);
//        fp2_print(b);
////        printf ("a0 %" PRIu64 "\n", *a[0]);
////        printf ("a1 %" PRIu64 "\n", *a[1]);
////        printf ("b0 %" PRIu64 "\n", *b[0]);
////        printf ("b1 %" PRIu64 "\n", *b[1]);
        /* Karatsuba algorithm. */
        /* t2 = a_0 + a_1, t1 = b_0 + b_1. */


        fp_add(t2, a[0], a[1]);
//        printf("t2:");
//        fp_print(t2);
        fp_add(t1, b[0], b[1]);
//        printf("b0:");
//        fp_print(b[0]);
//        printf("b1:");
//        fp_print(b[1]);
//        printf("t1:");
//        fp_print(t1);
////        printf ("t2 %" PRIu64 "\n", *t2);
////        printf ("t1 %" PRIu64 "\n", *t1);

        /* t3 = (a_0 + a_1) * (b_0 + b_1). */
        fp_muln_low(t3, t2, t1);
////        printf("t3:");
//        fp_print(t3);

////        printf ("t3 %" PRIu64 "\n", *t3);

        /* t0 = a_0 * b_0, t4 = a_1 * b_1. */
        fp_muln_low(t0, a[0], b[0]);
//        printf("t0:");
//        fp_print(t0);
////        printf ("t0 %" PRIu64 "\n", *t0);

        fp_muln_low(t4, a[1], b[1]);
//        printf("t4:");
//        fp_print(t4);
////        printf ("t4 %" PRIu64 "\n", *t4);


        /* t2 = (a_0 * b_0) + (a_1 * b_1). */
        fp_addc_low(t2, t0, t4);
//        printf("t2:");
//        fp_print(t2);

////        printf ("t2 %" PRIu64 "\n", *t2);

        /* t1 = (a_0 * b_0) + i^2 * (a_1 * b_1). */
        fp_subc_low(t1, t0, t4);
//        printf("t1:");
//        fp_print(t1);

////        printf ("t1 %" PRIu64 "\n", *t1);

        /* t1 = u^2 * (a_1 * b_1). */
        for (int i = -1; i > fp_prime_get_qnr(); i--) {
         fp_subc_low(t1, t1, t4);
        }
        for (int i = 1; i < fp_prime_get_qnr(); i++) {
         fp_addc_low(t1, t1, t4);
        }
        /* c_0 = t1 mod p. */
//        printf("t1:");
//        fp_print(t1);
        fp_rdc(c[0], t1);

// TODO debug fp_rdc valszeg ebben van a hiba!

        /* t4 = t3 - t2. */
	fp_subc_low(t4, t3, t2);
//        printf("t4:");
//        fp_print(t4);

////        printf ("t4 %" PRIu64 "\n", *t4);
	/* c_1 = t4 mod p. */
	fp_rdc(c[1], t4);

//       printf("result in fp2_mul_basic... \n");
//       printf ("%" PRIu64 "\n", *c[0]);
//       printf ("%" PRIu64 "\n", *c[1]);
//        fp2_print(c);
 free(t0);
 free(t1);
 free(t2);
 free(t3);
 free(t4);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_exp(fp_t c, const fp_t a, const bn_t b) {
 fp_exp_basic(c,a,b);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_inv(fp_t c, const fp_t a) {
        fp_inv_basic(c, a);
//        fp_inv_exgcd(c, a);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_add_basic(fp2_t c, fp2_t a, fp2_t b) {
  fp_add_basic(c[0], a[0], b[0]);
  fp_add_basic(c[1], a[1], b[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_neg_basic(fp_t c, const fp_t a) {
        if (fp_is_zero(a)) {
                fp_zero(c);
        } else {
                fp_subn_low(c, shared_prime, a);
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_neg(fp_t c, const fp_t a) {
  fp_neg_basic(c,a);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_mul_dig(fp_t c, const fp_t a, dig_t b) {
        dv_t t;
        fp_prime_conv_dig(t, b);
        fp_mul(c, a, t);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_neg(fp2_t c, fp2_t a) {
        fp_neg(c[0], a[0]);
        fp_neg(c[1], a[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_inv(fp2_t c, fp2_t a) {
	fp_t t0, t1;

//       printf("INPUT in fp2_inv... \n");
//       printf ("a0 %" PRIu64 "\n", *(a[0]) );
//       printf ("a1 %" PRIu64 "\n", *(a[0] + 1) );
//       printf ("a2 %" PRIu64 "\n", *(a[0] + 2) );
//       printf ("a3 %" PRIu64 "\n", *(a[0] + 3) );
//       printf ("a4 %" PRIu64 "\n", *(a[0] + 4) );
//       printf ("a5 %" PRIu64 "\n", *(a[0] + 5) );

// printf("1. fp2_inv ...\n");
        t0 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
// printf("2. fp2_inv ...\n");
        t1 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
// printf("3. fp2_inv ...\n");
		/* t0 = a_0^2, t1 = a_1^2. */
		fp_sqr(t0, a[0]);
//       printf("1. t0 ... \n");
//       printf ("t00 %" PRIu64 "\n", *(t0) );
//       printf ("t01 %" PRIu64 "\n", *(t0 + 1) );
//       printf ("t02 %" PRIu64 "\n", *(t0 + 2) );
//       printf ("t03 %" PRIu64 "\n", *(t0 + 3) );
//       printf ("t04 %" PRIu64 "\n", *(t0 + 4) );
//       printf ("t05 %" PRIu64 "\n", *(t0 + 5) );
// printf("4. fp2_inv ...\n");
		fp_sqr(t1, a[1]);
//       printf("2. t1 ... \n");
//       printf ("t10 %" PRIu64 "\n", *(t1) );
//       printf ("t11 %" PRIu64 "\n", *(t1 + 1) );
//       printf ("t12 %" PRIu64 "\n", *(t1 + 2) );
//       printf ("t13 %" PRIu64 "\n", *(t1 + 3) );
//       printf ("t14 %" PRIu64 "\n", *(t1 + 4) );
//       printf ("t15 %" PRIu64 "\n", *(t1 + 5) );

// printf("5. fp2_inv ...\n");
		/* t1 = 1/(a_0^2 + a_1^2). */
#ifndef FP_QNRES
		if (fp_prime_get_qnr() != -1) {
			if (fp_prime_get_qnr() == -2) {
// printf("6. fp2_inv ...\n");
				fp_dbl(t1, t1);
//       printf("3. t1 ... \n");
//       printf ("t10 %" PRIu64 "\n", *(t1) );
//       printf ("t11 %" PRIu64 "\n", *(t1 + 1) );
//       printf ("t12 %" PRIu64 "\n", *(t1 + 2) );
//       printf ("t13 %" PRIu64 "\n", *(t1 + 3) );
//       printf ("t14 %" PRIu64 "\n", *(t1 + 4) );
//       printf ("t15 %" PRIu64 "\n", *(t1 + 5) );

// printf("7. fp2_inv ...\n");
				fp_add(t0, t0, t1);
//       printf("4. t0 ... \n");
//       printf ("t00 %" PRIu64 "\n", *(t0) );
//       printf ("t01 %" PRIu64 "\n", *(t0 + 1) );
//       printf ("t02 %" PRIu64 "\n", *(t0 + 2) );
//       printf ("t03 %" PRIu64 "\n", *(t0 + 3) );
//       printf ("t04 %" PRIu64 "\n", *(t0 + 4) );
//       printf ("t05 %" PRIu64 "\n", *(t0 + 5) );

			} else {
				if (fp_prime_get_qnr() < 0) {
// printf("8. fp2_inv ...\n");
					fp_mul_dig(t1, t1, -fp_prime_get_qnr());
//       printf("5. t1 ... \n");
//       printf ("t10 %" PRIu64 "\n", *(t1) );
//       printf ("t11 %" PRIu64 "\n", *(t1 + 1) );
//       printf ("t12 %" PRIu64 "\n", *(t1 + 2) );
//       printf ("t13 %" PRIu64 "\n", *(t1 + 3) );
//       printf ("t14 %" PRIu64 "\n", *(t1 + 4) );
//       printf ("t15 %" PRIu64 "\n", *(t1 + 5) );

// printf("9. fp2_inv ...\n");
					fp_add(t0, t0, t1);
//       printf("6. t0 ... \n");
//       printf ("t00 %" PRIu64 "\n", *(t0) );
//       printf ("t01 %" PRIu64 "\n", *(t0 + 1) );
//       printf ("t02 %" PRIu64 "\n", *(t0 + 2) );
//       printf ("t03 %" PRIu64 "\n", *(t0 + 3) );
//       printf ("t04 %" PRIu64 "\n", *(t0 + 4) );
//       printf ("t05 %" PRIu64 "\n", *(t0 + 5) );

				} else {
// printf("10. fp2_inv ...\n");
					fp_mul_dig(t1, t1, fp_prime_get_qnr());
//       printf("8. t1 ... \n");
//       printf ("t10 %" PRIu64 "\n", *(t1) );
//       printf ("t11 %" PRIu64 "\n", *(t1 + 1) );
//       printf ("t12 %" PRIu64 "\n", *(t1 + 2) );
//       printf ("t13 %" PRIu64 "\n", *(t1 + 3) );
//       printf ("t14 %" PRIu64 "\n", *(t1 + 4) );
//       printf ("t15 %" PRIu64 "\n", *(t1 + 5) );

					fp_sub(t0, t0, t1);
//       printf("7. t0 ... \n");
//       printf ("t00 %" PRIu64 "\n", *(t0) );
//       printf ("t01 %" PRIu64 "\n", *(t0 + 1) );
//       printf ("t02 %" PRIu64 "\n", *(t0 + 2) );
//       printf ("t03 %" PRIu64 "\n", *(t0 + 3) );
//       printf ("t04 %" PRIu64 "\n", *(t0 + 4) );
//       printf ("t05 %" PRIu64 "\n", *(t0 + 5) );
				}
			}
		} else {

			fp_add(t0, t0, t1);
//       printf("10. t0 ... \n");
//       printf ("t00 %" PRIu64 "\n", *(t0) );
//       printf ("t01 %" PRIu64 "\n", *(t0 + 1) );
//       printf ("t02 %" PRIu64 "\n", *(t0 + 2) );
//       printf ("t03 %" PRIu64 "\n", *(t0 + 3) );
//       printf ("t04 %" PRIu64 "\n", *(t0 + 4) );
//       printf ("t05 %" PRIu64 "\n", *(t0 + 5) );

		}
#else
		fp_add(t0, t0, t1);
//       printf("11. t0 ... \n");
//       printf ("t00 %" PRIu64 "\n", *(t0) );
//       printf ("t01 %" PRIu64 "\n", *(t0 + 1) );
//       printf ("t02 %" PRIu64 "\n", *(t0 + 2) );
//       printf ("t03 %" PRIu64 "\n", *(t0 + 3) );
//       printf ("t04 %" PRIu64 "\n", *(t0 + 4) );
//       printf ("t05 %" PRIu64 "\n", *(t0 + 5) );
#endif
// printf("11. fp2_inv ...\n");
		fp_inv(t1, t0);
//       printf("9. t1 ... \n");
//       printf ("t10 %" PRIu64 "\n", *(t1) );
//       printf ("t11 %" PRIu64 "\n", *(t1 + 1) );
//       printf ("t12 %" PRIu64 "\n", *(t1 + 2) );
//       printf ("t13 %" PRIu64 "\n", *(t1 + 3) );
//       printf ("t14 %" PRIu64 "\n", *(t1 + 4) );
//       printf ("t15 %" PRIu64 "\n", *(t1 + 5) );

// printf("12. fp2_inv ...\n");
		/* c_0 = a_0/(a_0^2 + a_1^2). */
		fp_mul(c[0], a[0], t1);
// printf("13. fp2_inv ...\n");
		/* c_1 = - a_1/(a_0^2 + a_1^2). */
		fp_mul(c[1], a[1], t1);
// printf("14. fp2_inv ...\n");
		fp_neg(c[1], c[1]);
// printf("15. fp2_inv ...\n");
 free(t0);
 free(t1);
// printf("leaving fp2_inv ...\n");
//       printf("result in fp2_inv... \n");
//       printf ("c0 %" PRIu64 "\n", *(c[0]) );
//       printf ("c1 %" PRIu64 "\n", *(c[0] + 1) );
//       printf ("c2 %" PRIu64 "\n", *(c[0] + 2) );
//       printf ("c3 %" PRIu64 "\n", *(c[0] + 3) );
//       printf ("c4 %" PRIu64 "\n", *(c[0] + 4) );
//       printf ("c5 %" PRIu64 "\n", *(c[0] + 5) );

 
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t fp_add1_low(dig_t *c, const dig_t *a, dig_t digit) {
        int i;
        dig_t carry, r0;

        carry = digit;
        for (i = 0; i < RLC_FP_DIGS && carry; i++, a++, c++) {
                r0 = (*a) + carry;
                carry = (r0 < carry);
                (*c) = r0;
        }
        for (; i < RLC_FP_DIGS; i++, a++, c++) {
                (*c) = (*a);
        }
        return carry;
}

__device__
#if INLINE == 0
__noinline__
#endif
void dv_copy_cond(dig_t *c, const dig_t *a, int digits, dig_t cond) {
        dig_t mask, t;

        mask = -cond;
        for (int i = 0; i < digits; i++) {
                t = (a[i] ^ c[i]) & mask;
                c[i] ^= t;
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_add_dig(fp_t c, const fp_t a, dig_t b) {
#if FP_RDC == MONTY
        if (b == 1) {
// TODO is this OK?
//                fp_add(c, a, core_get()->one.dp);
                fp_add(c, a, shared_one);
        } else {
                fp_t t;

                fp_null(t); 

                        fp_new(t);

                        fp_set_dig(t, b);
                        fp_add(c, a, t);
        }
#else
        dig_t carry;

        carry = fp_add1_low(c, a, b);
        if (carry || dv_cmp(c, shared_prime, RLC_FP_DIGS) != RLC_LT) {
                carry = fp_subn_low(c, c, shared_prime);
        }
#endif
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_add_dig(fp2_t c, const fp2_t a, dig_t dig) {
        fp_add_dig(c[0], a[0], dig);
        fp_copy(c[1], a[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
/**
 * Simplified SWU mapping.
 */
#define EP2_MAP_COPY_COND(O, I, C)                                                       \
        do {                                                                                 \
                dv_copy_cond(O[0], I[0], RLC_FP_DIGS, C);                                        \
                dv_copy_cond(O[1], I[1], RLC_FP_DIGS, C);                                        \
        } while (0)


__device__
#if INLINE == 0
__noinline__
#endif
/* caution: this function overwrites k, which it uses as an auxiliary variable */
int fp2_sgn0(const fp2_t t, bn_t k) {
        const int t_0_zero = fp_is_zero(t[0]);

//        printf("1. fp2_sgn0 called, now iside...\n");
        fp_prime_back(k, t[0]);
//        printf("2. fp2_sgn0 called, now iside...\n");
        const int t_0_neg = bn_get_bit(k, 0);
//        printf("3. fp2_sgn0 called, now iside...\n");

        fp_prime_back(k, t[1]);
//        printf("4. fp2_sgn0 called, now iside...\n");
        const int t_1_neg = bn_get_bit(k, 0);
//        printf("5. fp2_sgn0 called, now iside...\n");

        /* t[0] == 0 ? sgn0(t[1]) : sgn0(t[0]) */
        return t_0_neg | (t_0_zero & t_1_neg);
}

__device__
#if INLINE == 0
__noinline__
#endif
int fp2_is_zero(fp2_t a) {
        return fp_is_zero(a[0]) && fp_is_zero(a[1]);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_copy(fp2_t c, fp2_t a) {

//  if( c == NULL){
//    printf("c has problems.... \n");
//   }
//   else{
//    printf("c is OK .... \n");
//   } 
//
//  if( a == NULL){
//    printf("a has problems.... \n");
//   }
//   else{
//    printf("a is OK .... \n");
//   } 
//
//        printf("1. fp_copy call...\n");
        fp_copy(c[0], a[0]);
//        printf("2. fp_copy call...\n");
        fp_copy(c[1], a[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
int dv_cmp_const(const dig_t *a, const dig_t *b, int size) {
        dig_t r = 0;

        for (int i = 0; i < size; i++) {
                r |= a[i] ^ b[i];
        }

        return (r == 0 ? RLC_EQ : RLC_NE);
}
__device__
#if INLINE == 0
__noinline__
#endif
int fp_cmp(const fp_t a, const fp_t b) {
        return dv_cmp_const(a, b, RLC_FP_DIGS);
}
__device__
#if INLINE == 0
__noinline__
#endif
int fp_cmp_dig(const fp_t a, dig_t b) {
        fp_t t;
        int r = RLC_EQ;

        fp_null(t);
        fp_new(t);
        fp_prime_conv_dig(t, b);
        r = fp_cmp(a, t);

        return r;
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_rsh(bn_t c, const bn_t a, int bits) {
        int digits = 0;

        bn_copy(c, a);

        if (bits <= 0) {
                return;
        }

        RLC_RIP(bits, digits, bits);

        if (digits > 0) {
                dv_rshd(c->dp, a->dp, a->used, digits);
        }
        c->used = a->used - digits;
        c->sign = a->sign;

        if (c->used > 0 && bits > 0) {
                if (digits == 0 && c != a) {
                        bn_rshb_low(c->dp, a->dp + digits, a->used - digits, bits);
                } else {
                        bn_rshb_low(c->dp, c->dp, c->used, bits);
                }
        }
        bn_trim(c);
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_add_dig(bn_t c, const bn_t a, dig_t b) {
 dig_t carry;
 bn_grow(c, a->used);
 if (a->sign == RLC_POS) {
  carry = bn_add1_low(c->dp, a->dp, b, a->used);
  if (carry) {
   bn_grow(c, a->used + 1);
   c->dp[a->used] = carry;
  }
  c->used = a->used + carry;
  c->sign = RLC_POS;
  } 
 else {
  /* If a < 0 && |a| >= b, compute c = -(|a| - b). */
  if (a->used > 1 || a->dp[0] >= b) {
   carry = bn_sub1_low(c->dp, a->dp, b, a->used);
   c->used = a->used;
   c->sign = RLC_NEG;
   } else {
   /* If a < 0 && |a| < b. */
   if (a->used == 1) {
    c->dp[0] = b - a->dp[0];
    } else {
     c->dp[0] = b;
    }
    c->used = 1;
    c->sign = RLC_POS;
    }
 }
 bn_trim(c);
}
__device__
#if INLINE == 0
__noinline__
#endif
int bn_is_even(const bn_t a) {
        if (bn_is_zero(a)) {
                return 1;
        }
        if ((a->dp[0] & 0x01) == 0) {
                return 1;
        }
        return 0;
}  
__device__
#if INLINE == 0
__noinline__
#endif
int fp_srt(fp_t c, const fp_t a) {

	bn_t e;

	fp_t t0;
	fp_t t1;

	int r = 0;

        e  = (bn_t ) malloc(sizeof(bn_st));
        e->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
        e->alloc = RLC_BN_SIZE;
        e->sign = RLC_POS;

        t0 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
        t1 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));

	bn_null(e);
	fp_null(t0);
	fp_null(t1);

	if (fp_is_zero(a)) {
		fp_zero(c);
		return 1;
	}

		bn_new(e);
		fp_new(t0);
		fp_new(t1);

		/* Make e = p. */
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, shared_prime, RLC_FP_DIGS);

//		if (fp_prime_get_mod8() == 3 || fp_prime_get_mod8() == 7) {
			/* Easy case, compute a^((p + 1)/4). */
			bn_add_dig(e, e, 1);
			bn_rsh(e, e, 2);

			fp_exp(t0, a, e);
			fp_sqr(t1, t0);
			r = (fp_cmp(t1, a) == RLC_EQ);
			fp_copy(c, t0);
//		} else {
//			int f = 0, m = 0;
//
//			/* First, check if there is a root. Compute t1 = a^((p - 1)/2). */
//			bn_rsh(e, e, 1);
//			fp_exp(t0, a, e);
//
//			if (fp_cmp_dig(t0, 1) != RLC_EQ) {
//				/* Nope, there is no square root. */
//				r = 0;
//			} else {
//				r = 1;
//				/* Find a quadratic non-residue modulo p, that is a number t2
//				 * such that (t2 | p) = t2^((p - 1)/2)!= 1. */
//				do {
//// TODO is this deterministic?
//					fp_rand(t1);
//					fp_exp(t0, t1, e);
//				} while (fp_cmp_dig(t0, 1) == RLC_EQ);
//
//				/* Write p - 1 as (e * 2^f), odd e. */
//				bn_lsh(e, e, 1);
//				while (bn_is_even(e)) {
//					bn_rsh(e, e, 1);
//					f++;
//				}
//
//				/* Compute t2 = t2^e. */
//				fp_exp(t1, t1, e);
//
//				/* Compute t1 = a^e, c = a^((e + 1)/2) = a^(e/2 + 1), odd e. */
//				bn_rsh(e, e, 1);
//				fp_exp(t0, a, e);
//				fp_mul(e->dp, t0, a);
//				fp_sqr(t0, t0);
//				fp_mul(t0, t0, a);
//				fp_copy(c, e->dp);
//
//				while (1) {
//					if (fp_cmp_dig(t0, 1) == RLC_EQ) {
//						break;
//					}
//					fp_copy(e->dp, t0);
//					for (m = 0; (m < f) && (fp_cmp_dig(t0, 1) != RLC_EQ); m++) {
//						fp_sqr(t0, t0);
//					}
//					fp_copy(t0, e->dp);
//					for (int i = 0; i < f - m - 1; i++) {
//						fp_sqr(t1, t1);
//					}
//					fp_mul(c, c, t1);
//					fp_sqr(t1, t1);
//					fp_mul(t0, t0, t1);
//					f = m;
//				}
//			}
//		}
	return r;
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t fp_rsh1_low(dig_t *c, const dig_t *a) {
        int i;
        dig_t r, carry;

        c += RLC_FP_DIGS - 1;
        a += RLC_FP_DIGS - 1;
        carry = 0;
        for (i = RLC_FP_DIGS - 1; i >= 0; i--, a--, c--) {
                /* Get the least significant bit. */
                r = *a & 0x01;
                /* Shift the operand and insert the carry. */
                carry <<= RLC_DIG - 1;
                *c = (*a >> 1) | carry;
                /* Update the carry. */
                carry = r;
        }
        return carry;
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_hlv_basic(fp_t c, const fp_t a) {
        dig_t carry = 0;

        if (a[0] & 1) {
                carry = fp_addn_low(c, a, shared_prime);
        } else {
                fp_copy(c, a);
        }
        fp_rsh1_low(c, c);
        if (carry) {
                c[RLC_FP_DIGS - 1] ^= ((dig_t)1 << (RLC_DIG - 1));
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp_hlv(fp_t c, const fp_t a) {
 fp_hlv_basic(c,a);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_zero(fp2_t a) {
        fp_zero(a[0]);
        fp_zero(a[1]);
}

__device__
#if INLINE == 0
__noinline__
#endif
int fp2_srt(fp2_t c, fp2_t a) {
 int r = 0;
 fp_t t0;        
 fp_t t1;        
 fp_t t2;

 t0 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
 t1 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
 t2 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));

// printf("1. fp2_srt \n");
 if (fp2_is_zero(a)) {
  fp2_zero(c);
  free(t0);
  free(t1);
  free(t2);
  return 1;
 }

 if (fp_is_zero(a[1])) {
  /* special case: either a[0] is square and sqrt is purely 'real'
  * or a[0] is non-square and sqrt is purely 'imaginary' */
  r = 1;
  if (fp_srt(t0, a[0])) {
   fp_copy(c[0], t0);
   fp_zero(c[1]);
//   printf("2. fp2_srt \n");
  } 
  else {
  /* Compute a[0]/i^2. */
#ifdef FP_QNRES
   fp_copy(t0, a[0]);
#else
   if (fp_prime_get_qnr() == -2) {
    fp_hlv(t0, a[0]);
   } 
   else {
//    printf("3. fp2_srt \n");
    fp_set_dig(t0, -fp_prime_get_qnr());
    fp_inv(t0, t0);
//    printf("4. fp2_srt \n");
    fp_mul(t0, t0, a[0]);
   }
#endif
  fp_neg(t0, t0);
//    printf("5. fp2_srt \n");
  fp_zero(c[0]);
//    printf("6. fp2_srt \n");
  if (!fp_srt(c[1], t0)) {
   /* should never happen! */
   printf("Problem in squaring field elements...\n");
  }
  }
 } 
 else {
  /* t0 = a[0]^2 - i^2 * a[1]^2 */
  fp_sqr(t0, a[0]);
  fp_sqr(t1, a[1]);
 
  for (int i = -1; i > fp_prime_get_qnr(); i--) {
   fp_add(t0, t0, t1);
  }
 
  fp_add(t0, t0, t1);
 
  if (fp_srt(t1, t0)) {
   /* t0 = (a_0 + sqrt(t0)) / 2 */
   fp_add(t0, a[0], t1);
   fp_hlv(t0, t0);
   if (!fp_srt(t2, t0)) {
    /* t0 = (a_0 - sqrt(t0)) / 2 */
    fp_sub(t0, a[0], t1);
    fp_hlv(t0, t0);
    if (!fp_srt(t2, t0)) {
     /* should never happen! */
     printf("Problem in squaring field elements...\n");
    }
    
    /* c_0 = sqrt(t0) */
    fp_copy(c[0], t2);
    /* c_1 = a_1 / (2 * sqrt(t0)) */
    fp_dbl(t2, t2);
    fp_inv(t2, t2);
    fp_mul(c[1], a[1], t2);
    r = 1;
   }
  }
  free(t0);
  free(t1);
  free(t2);
  return r;
 }
}
__device__
#if INLINE == 0
__noinline__
#endif
char util_conv_char(dig_t i) {
#if WSIZE == 8 || WSIZE == 16
        /* Avoid tables to save up some memory. This is not performance-critical. */
        if (i < 10) {
                return i + '0';
        }
        if (i < 36) {
                return (i - 10) + 'A';
        }
        if (i < 62) {
                return (i - 36) + 'a';
        }
        if (i == 62) {
                return '+';
        } else {
                return '/';
        }
#else
        /* Use a table. */
        static const char conv_table[] =
                        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
        return conv_table[i];
#endif
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_mul_dig(bn_t c, const bn_t a, dig_t b) {
 bn_grow(c, a->used + 1);
 c->sign = a->sign;
 c->dp[a->used] = bn_mul1_low(c->dp, a->dp, b, a->used);
 c->used = a->used + 1;
 bn_trim(c);
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_read_str(bn_t a, const char *str, int len, int radix) {
        int sign, i, j;
        char c;

// printf("1. bn_read_str \n");
        bn_zero(a);
// printf("2. bn_read_str \n");

        if (radix < 2 || radix > 64) {
                printf("radix < 2 || radix > 64 in bn_read_str...");
                return;
        }

// printf("3. bn_read_str \n");
        j = 0;  
        if (str[0] == '-') {
                j++;
                sign = RLC_NEG;
        } else {
                sign = RLC_POS;
        }
//        printf("RLC_DIG %d \n", RLC_DIG);
//        printf("len %d \n", len);
//        printf("radix %d \n", radix);
//        printf("util_bits_dig(radix), %d \n", util_bits_dig(radix));
//        printf("len * util_bits_dig(radix), %d \n", len * util_bits_dig(radix));
//        printf("RLC_CEIL(len * util_bits_dig(radix), RLC_DIG) %d \n ", RLC_CEIL(len * util_bits_dig(radix), RLC_DIG) );

// printf("4. bn_read_str \n");
                bn_grow(a, RLC_CEIL(len * util_bits_dig(radix), RLC_DIG));
// printf("5. bn_read_str \n");
//        printf("j %d \n", j);
                while (j < len) {
                        if (str[j] == 0) {
                                break;
                        }
                        c = (char)((radix < 36) ? RLC_UPP(str[j]) : str[j]);
// printf("6. bn_read_str \n");
                        for (i = 0; i < 64; i++) {
// printf("7. bn_read_str \n");
                                if (c == util_conv_char(i)) {
                                        break;
                                }
                        }

                        if (i < radix) {
// printf("8. bn_read_str \n");
//                                printf("a->used %d \n", a->used);
                                bn_mul_dig(a, a, (dig_t)radix);
// printf("9. bn_read_str \n");
                                bn_add_dig(a, a, (dig_t)i);
                        } else {
                                break;
                        }
                        j++;
                }

                a->sign = sign;
// printf("10. bn_read_str \n");
}

__device__ 
#if INLINE == 0
__noinline__
#endif
void bn_print(const bn_t a) {
        int i;

        if (a->sign == RLC_NEG) {
               printf("-");
        }
        if (a->used == 0) {
                printf("0\n");
        } else {
                util_print_dig(a->dp[a->used - 1], 0);
                for (i = a->used - 2; i >= 0; i--) {
                        util_print_dig(a->dp[i], 1);
                }
                printf("\n");
        }
}
__device__ 
#if INLINE == 0
__noinline__
#endif
void fp_read_str(fp_t a, const char *str, int len, int radix) {
 bn_t t;

 t  = (bn_t ) malloc(sizeof(bn_st));
 t->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 t->alloc = RLC_BN_SIZE;
 t->sign = RLC_POS;

 bn_read_str(t, str, len, radix);
//                printf("Printing t in fp_read_str..\n");
//                bn_print(t);

 if (bn_is_zero(t)) {
  fp_zero(a);
 } 
 else {
  if (t->used == 1) {
//                printf("Printing a 1 in fp_read_str..\n");
//                fp_print(a);
   fp_prime_conv_dig(a, t->dp[0]);
//                printf("Printing a 2 in fp_read_str..\n");
//                fp_print(a);

   if (bn_sign(t) == RLC_NEG) {
    fp_neg(a, a);
//                printf("Printing a 3 in fp_read_str..\n");
//                fp_print(a);

   }
  } 
  else {
   fp_prime_conv(a, t);
//                printf("Printing a 4 in fp_read_str..\n");
//                fp_print(a);

   }
 }
 free(t->dp);
 free(t);
}
__device__
#if INLINE == 0
__noinline__
#endif
size_t strlen_cuda(const char *str)
{
	const char *s;
	for (s = str; *s; ++s)
		;
	return (s - str);
}
__device__
#if INLINE == 0
__noinline__
#endif
char * strchr_cuda(register const char *s, int c)
{
  do {
    if (*s == c)
      {
        return (char*)s;
      }
  } while (*s++);
  return (0);
}
/**
 * Reads a sequence of polynomial coefficients from semicolon separated string.
 *
 * @param[out] coeffs		- the resulting coefficients.
 * @param[in] str			- the input string.
 */
__device__ __noinline__
__noinline__
int ep2_curve_get_coeffs(fp2_t *coeffs, const char *str) {
	int degree = 0;
	unsigned offset = 0;

	if (str[0] == '\0') {
		/* need nonzero strlen */
		printf("str[0] == '\0' in ep2_curve_get_coeffs... \n");
		return 0;
	}
	for (; degree < RLC_EPX_CTMAP_MAX; ++degree) {
		/* first coeff */
		const char *end = strchr_cuda(str + offset, ',');
		if (end == NULL) {
			/* should not happen --- means there's no second coeff */
			printf("end == NULL...\n");
		}
		unsigned len = end - str - offset;
		fp_read_str(coeffs[degree][0], str + offset, len, 16);
		offset += len + 1; /* move to after ',' */

		/* second coeff */
		end = strchr_cuda(str + offset, ';');
		if (end == NULL) {
			/* last one */
			fp_read_str(coeffs[degree][1], str + offset, strlen_cuda(str + offset), 16);
			break;
		}
		len = end - str - offset;
		fp_read_str(coeffs[degree][1], str + offset, len, 16);
		offset += len + 1; /* move to after ';' */
	}
	if (degree == RLC_EPX_CTMAP_MAX) {
		/* ran out of space before converting all coeffs */
		printf("degree == RLC_EPX_CTMAP_MAX...\n");
	}
	return degree;
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_set_dig(fp2_t a, dig_t b) {
        fp_set_dig(a[0], b);
        fp_zero(a[1]);
}
/**
 * Normalizes a point represented in projective coordinates.
 *
 * @param r                     - the result.
 * @param p                     - the point to normalize.
 */
__device__
#if INLINE == 0
__noinline__
#endif
static void ep2_norm_imp(ep2_t r, ep2_t p, int inverted) {
 if (p->coord != BASIC) {
  fp2_t t0, t1;

 t0[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t0[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 t1[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  if (inverted) {
   fp2_copy(t1, p->z);
  } else {
   fp2_inv(t1, p->z);
  }
   fp2_sqr_basic(t0, t1);
   fp2_mul_basic(r->x, p->x, t0);
   fp2_mul_basic(t0, t0, t1);
   fp2_mul_basic(r->y, p->y, t0);
   fp2_set_dig(r->z, 1);
  }
  r->coord = BASIC;
}
__device__
#if INLINE == 0
__noinline__
#endif
int ep2_is_infty(ep2_t p) {
        return (fp2_is_zero(p->z) == 1);
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep2_set_infty(ep2_t p) {
        fp2_zero(p->x);
        fp2_zero(p->y);
        fp2_zero(p->z);
        p->coord = BASIC;
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep2_copy(ep2_t r, ep2_t p) {
        fp2_copy(r->x, p->x);
        fp2_copy(r->y, p->y);
        fp2_copy(r->z, p->z);
        r->coord = p->coord;
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep2_norm(ep2_t r, ep2_t p) {
 if (ep2_is_infty(p)) {
  ep2_set_infty(r);
 return;
 }
 if (p->coord == BASIC) {
  /* If the point is represented in affine coordinates, we just copy it. */
  ep2_copy(r, p);
 }
#if EP_ADD == PROJC || !defined(STRIP)
 ep2_norm_imp(r, p, 0);
#endif
}
// Evaluate a polynomial using Horner's rule
__device__
#if INLINE == 0
__noinline__
#endif
static void fp2_eval(fp2_t c, fp2_t a, fp2_t *coeffs, int deg) {
 fp2_copy(c, coeffs[deg]);                    
 for (int i = deg; i > 0; --i) {            
  fp2_mul_basic(c, c, a);                  
  fp2_add_basic(c, c, coeffs[i - 1]);     
  }                                       
}
__device__
#if INLINE == 0
__noinline__
#endif
void isogeny_map(ep2_t p){
 fp2_t t0, t1, t2, t3;

 t0[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t0[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 t1[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 t2[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t2[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 t3[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t3[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 /* XXX need to add real support for input projective points */
 printf("Normalizing the coordinates...\n");
 if (p->coord != BASIC) {            
  ep2_norm(p, p);                     
 }                                     
 iso2_t coeffs = shared_coeffs;
 printf("Evaluating the polynomial...\n");
 /* numerators */                             
 fp2_eval(t0, p->x, coeffs->xn, coeffs->deg_xn);
 fp2_eval(t1, p->x, coeffs->yn, coeffs->deg_yn);
 /* denominators */                           
 fp2_eval(t2, p->x, coeffs->yd, coeffs->deg_yd);
 fp2_eval(t3, p->x, coeffs->xd, coeffs->deg_xd);
 /* normalize if necessary */  

/* Y = Ny * Dx * Z^2. */                                                                                        
 fp2_mul_basic(p->y, p->y, t1);
 fp2_mul_basic(p->y, p->y, t3);
 /* Z = Dx * Dy, t1 = Z^2. */                                                                            \
 fp2_mul_basic(p->z, t2, t3);
 fp2_sqr_basic(t1, p->z);
 fp2_mul_basic(p->y, p->y, t1);
 /* X = Nx * Dy * Z. */                                                                                          \
 fp2_mul_basic(p->x, t0, t2);
 fp2_mul_basic(p->x, p->x, p->z);
 p->coord = PROJC;

}

__device__ __noinline__
void map_scalar_to_curve(ep2_t p, fp2_t t){
 fp2_t t0, t1, t2, t3;

 char str[4 * RLC_FP_BYTES + 1];
 fp_t *mBoverA;
 fp_t *a;
 fp_t *b;
 fp_t *u;  

 a = (fp_t*)malloc(RLC_BN_SIZE * sizeof(dig_t));
 b = (fp_t*)malloc(RLC_BN_SIZE * sizeof(dig_t));
 u = (fp_t*)malloc(RLC_BN_SIZE * sizeof(dig_t));
 
 t0[0] = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
 t0[1] = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));

 t1[0] = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
 t1[1] = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));

 t2[0] = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
 t2[1] = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));

 t3[0] = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
 t3[1] = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));

 mBoverA = shared_c[0];
 a       = shared_c[2];
 b       = shared_c[3];

// Precomputes constants
// ez a beolvasás valszeg nem jó...
 shared_map_u[0] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
 shared_map_u[1] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));

 memcpy(str, B12_P381_MAPU0, sizeof(B12_P381_MAPU0));
 fp_read_str(shared_map_u[0], str, 2, 16);
 memcpy(str, B12_P381_MAPU1, sizeof(B12_P381_MAPU1));
 fp_read_str(shared_map_u[1], str, 2, 16);

 u       = shared_map_u;

// print_line();
// printf("u after fp_read_str ... \n");
// print_multiple_precision(shared_map_u[0],1);
// print_multiple_precision(shared_map_u[1],1);
// fp2_print(shared_map_u);
 printf("now precomputing the isomap constants...\n");
 /* SSWU map constants */
 /* constants 3 and 4 are a and b for the curve or isogeny */
 shared_c[0][0]   = (fp_t )malloc(RLC_BN_SIZE * sizeof(dig_t));
 shared_c[0][1]   = (fp_t )malloc(RLC_BN_SIZE * sizeof(dig_t));
 shared_c[1][0]   = (fp_t )malloc(RLC_BN_SIZE * sizeof(dig_t));
 shared_c[1][1]   = (fp_t )malloc(RLC_BN_SIZE * sizeof(dig_t));
 shared_c[2][0]   = (fp_t )malloc(RLC_BN_SIZE * sizeof(dig_t));
 shared_c[2][1]   = (fp_t )malloc(RLC_BN_SIZE * sizeof(dig_t));
 shared_c[3][0]   = (fp_t )malloc(RLC_BN_SIZE * sizeof(dig_t));
 shared_c[3][1]   = (fp_t )malloc(RLC_BN_SIZE * sizeof(dig_t));
 fp2_copy(shared_c[2], shared_coeffs->a);
 fp2_copy(shared_c[3], shared_coeffs->b);
 /* constant 1: -b / a */
 fp2_neg(shared_c[0], shared_c[2]);     /* c1 = -a */
 fp2_inv(shared_c[0], shared_c[0]);     /* c1 = -1 / a */
 fp2_mul_basic(shared_c[0], shared_c[0], shared_c[3]); /* c1 = -b / a */
// Precomputation ends here //
// Compute the SSWU Map
 printf("Computing the SSWU map ...\n");

 printf("t: \n");
 fp2_print(t);
 fp2_sqr_basic(t0, t);
 printf("t^2: \n");
 fp2_print(t0);

 printf("u:  \n");
 fp2_print(u);
 fp2_mul_basic(t0, t0, u);  /* t0 = u * t^2 */
 printf("u * t^2: \n");
 fp2_print(t0);
 fp2_sqr_basic(t1, t0);     /* t1 = u^2 * t^4 */
 printf("u^2 * t^4: \n");
 fp2_print(t1);
 fp2_add_basic(t2, t1, t0); /* t2 = u^2 * t^4 + u * t^2 */ 
 printf("u^2 * t^4 + u * t^2: \n");
 fp2_print(t2);
 printf("Computing the SSWU map finished...\n");

 /* handle the exceptional cases */  
 /* XXX(rsw) should be done projectively */   
 {                                            
  const int e1 = fp2_is_zero(t2);     
  fp2_neg(t3, u);         /* t3 = -u */      
  EP2_MAP_COPY_COND(t2, t3, e1);        /* exception: -u instead of u^2t^4 + ut^2 */ 
         fp2_inv(t2, t2);        /* t2 = -1/u or 1/(u^2 * t^4 + u*t^2) */
         fp2_add_dig(t3, t2, 1); /* t3 = 1 + t2 */                                
         EP2_MAP_COPY_COND(t2, t3, e1 == 0);      /* only add 1 if t2 != -1/u */         
 }                                                                              
 /* e1 goes out of scope */                                                    
                                                                              
 /* compute x1, g(x1) */                                                    
 printf("compute x1, g(x1)... \n");
 fp2_mul_basic(p->x, t2, mBoverA); /* -B / A * (1 + 1 / (u^2 * t^4 + u * t^2)) */
 fp2_sqr_basic(p->y, p->x);        /* x^2 */                                    
 fp2_add_basic(p->y, p->y, a);     /* x^2 + a */                               
 fp2_mul_basic(p->y, p->y, p->x);  /* x^3 + a x */                            
 fp2_add_basic(p->y, p->y, b);     /* x^3 + a x + b */                       
 printf("compute x1, g(x1) finished... \n");
 /* compute x2, g(x2) */                                            
 printf("compute x2, g(x2) ... \n");
 fp2_mul_basic(t2, t0, p->x); /* t2 = u * t^2 * x1 */                    
 fp2_mul_basic(t1, t0, t1);   /* t1 = u^3 * t^6 */                      
 fp2_mul_basic(t3, t1, p->y); /* t5 = g(t2) = u^3 * t^6 * g(p->x) */   
 printf("compute x2, g(x2) finished... \n");
//  /* XXX(rsw)                                                               */   
//  /* This should be done in constant time and without computing 2 sqrts.    */  
//  /* Avoiding a second sqrt relies on knowing the 2-adicity of the modulus. */ 
  if (!fp2_srt(p->y, p->y)) {                                                 
          /* try x2, g(x2) */                                                
          fp2_copy(p->x, t2);                                               
          if (!fp2_srt(p->y, t3)) {                                        
                  printf("+++++++++ Error +++++++++ \n");
                  printf("!fp2_srt(p->y, t3) in MAP calculation...\n");
                  printf("++++++++ !Error! ++++++++++ \n");
          }                                                              
  }    
  fp2_set_dig(p->z, 1);
  p->coord = BASIC;  
  free(t0[0]);
  free(t0[1]);
  free(t1[0]);
  free(t1[1]);
  free(t2[0]);
  free(t2[1]);
  free(t3[0]);
  free(t3[1]);
  return;
// }
}

/**
 * Configures a constant-time hash-to-curve function based on an isogeny map.
 *
 * @param[in] a0_str                    - the string representing the 1st element of the 'a' coefficient.
 * @param[in] a1_str                    - the string representing the 2nd element of the 'a' coefficient.
 * @param[in] b0_str                    - the string representing the 1st element of the 'b' coefficient.
 * @param[in] b1_str                    - the string representing the 2nd element of the 'b' coefficient.
 * @param[in] xn_str                    - the string representing the x numerator coefficients.
 * @param[in] xd_str                    - the string representing the x denominator coefficients.
 * @param[in] yn_str                    - the string representing the y numerator coefficients.
 * @param[in] yd_str                    - the string representing the y denominator coefficients.
 */
/* declaring this function inline suppresses unused function warnings */
__device__ __noinline__
void ep2_curve_set_ctmap(const char *a0_str, const char *a1_str, const char *b0_str, const char *b1_str, const char *xn_str, const char *xd_str, const char *yn_str, const char *yd_str) {

        shared_coeffs = (iso2_t )malloc(sizeof(iso2_st));

        shared_coeffs->a[0] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
        shared_coeffs->a[1] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));

        shared_coeffs->b[0] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
        shared_coeffs->b[1] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));

        for (unsigned i = 0; i < RLC_EPX_CTMAP_MAX; ++i) {
                shared_coeffs->xn[i][0] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
                shared_coeffs->xn[i][1] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
                shared_coeffs->xd[i][0] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
                shared_coeffs->xd[i][1] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
                shared_coeffs->yn[i][0] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
                shared_coeffs->yn[i][1] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
                shared_coeffs->yd[i][0] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
                shared_coeffs->yd[i][1] = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
        }


//        printf("a0_str: %d\n", strlen_cuda(a0_str));
//        printf("a1_str: %d\n", strlen_cuda(a1_str));
//        printf("b0_str: %d\n", strlen_cuda(b0_str));
//        printf("b1_str: %d\n", strlen_cuda(b1_str));
//
//        /* coefficients of isogenous curve */
//        fp_read_str(iso->a[0], a0_str, strlen_cuda(a0_str), 16);
//        fp_read_str(iso->a[1], a1_str, strlen_cuda(a1_str), 16);
//        fp_read_str(iso->b[0], b0_str, strlen_cuda(b0_str), 16);
//        fp_read_str(iso->b[1], b1_str, strlen_cuda(b1_str), 16);

        fp_read_str(shared_coeffs->a[0], a0_str, 1, 16);
        fp_read_str(shared_coeffs->a[1], a1_str, 2, 16);
        fp_read_str(shared_coeffs->b[0], b0_str, 3, 16);
        fp_read_str(shared_coeffs->b[1], b1_str, 3, 16);

        printf("Done reading a and b...\n");
        /* isogeny map coeffs */
        shared_coeffs->deg_xn = ep2_curve_get_coeffs(shared_coeffs->xn, xn_str);
        shared_coeffs->deg_xd = ep2_curve_get_coeffs(shared_coeffs->xd, xd_str);
        shared_coeffs->deg_yn = ep2_curve_get_coeffs(shared_coeffs->yn, yn_str);
        shared_coeffs->deg_yd = ep2_curve_get_coeffs(shared_coeffs->yd, yd_str);
        printf("Leaving ep2_curve_set_ctmap a and b...\n");
        return;

//        printf("xn: %d\n", shared_coeffs->deg_xn);
//        printf("xd: %d\n", shared_coeffs->deg_xd);
//        printf("yn: %d\n", shared_coeffs->deg_yn);
//        printf("yd: %d\n", shared_coeffs->deg_yd);
}




__device__
#if INLINE == 0
__noinline__
#endif
void signmessage(bn_t e, bn_t e2, int sequence){
 uint64_t carry;
 int neg;
 bn_t u, m, tt;
 fp_t r;
 fp2_t ttt;
 bn_st conv;
 bn_st one;
 ep2_t p;
 printf("sequence:  %d \n", sequence);
// print_line();
// printf("shared_prime: \n");
// print_multiple_precision(shared_prime,6);
// print_line();
 m = (bn_t )malloc(sizeof(bn_t)); 
 m->dp = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t)); 
 m->used = 6;
 for(int i=0; i < 6; i++){
  m->dp[i] = shared_prime[i];
 } 



 m->alloc = RLC_BN_SIZE;
 m->sign = RLC_POS;
 shared_prime_bn = m;
// Initialize u (the result of the Montgomery reduction) 
  u = (bn_t )malloc(sizeof(bn_t)); 
  u->dp = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t)); 
  u->used = 1;
  u->dp[0] = 0;
  u->alloc = RLC_BN_SIZE;
  u->sign = RLC_POS;
/////////////////////////////////////////////////////////////////////////
  one.dp = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
  one.used = 1;
  one.alloc = RLC_BN_SIZE;
  one.sign = RLC_POS;
  conv.dp = (dig_t *)malloc(RLC_BN_SIZE * sizeof(dig_t));
  conv.used = 1;
  conv.alloc = RLC_BN_SIZE;
  conv.sign = RLC_POS;
// Call the Montgomery reduction function

  bn_mod_pre_monty(u, m);

  shared_u = u->dp;
// Multiply by the Montgomery reduced prime (u)
  bn_set_dig(&one, 1);

// printf("\n---- one --- \n");
// for(int i=0; i < one.used; i++){
//  printf("one %d %" PRIu64 " \n",i, one.dp[i]);
// }
//  printf("1. one: \n");
//  print_multiple_precision(one.dp,6);
//  print_line();
  bn_lsh(&one, &one, RLC_FP_DIGS * RLC_DIG);
// printf("\n---- one 1--- \n");
// for(int i=0; i < one.used; i++){
//  printf("one %d %" PRIu64 " \n",i, one.dp[i]);
// }
//  printf("2. one: \n");
//  print_multiple_precision(one.dp,6);
//  print_line();

// Calculate 1 mod p
  bn_mod_basic(&one, &one, m);
// printf("\n---- one 2--- \n");
// for(int i=0; i < one.used; i++){
//  printf("one %d %" PRIu64 " \n",i, one.dp[i]);
// }
//  printf("3. one: \n");
//  print_multiple_precision(one.dp,6);
//  print_line();
  r = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  fp_add_basic(r, one.dp, one.dp);
// printf("\n---- one 3--- \n");
// for(int i=0; i < one.used; i++){
//  printf("one %d %" PRIu64 " \n",i, one.dp[i]);
// }
  tt = (bn_t ) malloc(sizeof(bn_st));
  tt->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
  tt->alloc = RLC_BN_SIZE;
  tt->sign = RLC_POS;
  bn_set_dig(u, RLC_FP_DIGS);
  bn_lsh(u, u, RLC_DIG_LOG);
//  printf("r: \n");
//  print_multiple_precision(r,6);
//  print_line();
//
//  printf("u: \n");
//  print_multiple_precision(u->dp,6);
//  print_line();
// printf("\n---- u  --- \n");
// for(int i=0; i < u->used; i++){
//  printf("u %d %" PRIu64 " \n",i, u->dp[i]);
// }
// printf("\n---- t --- \n");

  fp_exp_basic(conv.dp, r, u);
  conv.used = RLC_FP_DIGS;
  bn_trim(&(conv));

// printf("\n---- conv --- \n");
// for(int i=0; i < conv.used; i++){
//  printf("conv %d %" PRIu64 " \n",i, conv.dp[i]);
// }
/////////////////////////////////////////////////////////////////////////
// Ez nagyon gany megoldas...
  shared_conv[0] = conv.dp[0];
  shared_conv[1] = conv.dp[1];
  shared_conv[2] = conv.dp[2];
  shared_conv[3] = conv.dp[3];
  shared_conv[4] = conv.dp[4];
  shared_conv[5] = conv.dp[5];
  shared_one[0] = one.dp[0];
  shared_one[1] = one.dp[1];
  shared_one[2] = one.dp[2];
  shared_one[3] = one.dp[3];
  shared_one[4] = one.dp[4];
  shared_one[5] = one.dp[5];
  ttt[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  ttt[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

// e and e2 contain the sha256 converted message
// the message is reduced and loaded into ttt


//  printf("shared_conv: \n");
//  print_multiple_precision(shared_conv,6);
//  print_line();
//
//  printf("shared_one: \n");
//  print_multiple_precision(shared_one,6);
//  print_line();
//
//  printf("shared_u: \n");
//  print_multiple_precision(shared_u,6);
//  print_line();

  fp_prime_conv(ttt[0], e);
  fp_prime_conv(ttt[1], e2);

  printf("bID %d thID: %d ttt[0] %" PRIu64 " ttt[1] %" PRIu64 "\n",blockIdx.x, threadIdx.x,  *ttt[0], *ttt[1]);
  fp_print(ttt[0]);
  fp_print(ttt[1]);

/////////////////////////////////////////////////////////////////////////
  /* sign of t */                                                                
  neg = fp2_sgn0(ttt, e);
  printf("Setting the isogeny map ...\n");
// Calculate parameters for the curve isogeny
  ep2_curve_set_ctmap(B12_P381_ISO_A0, B12_P381_ISO_A1, B12_P381_ISO_B0, B12_P381_ISO_B1, B12_P381_ISO_XN, B12_P381_ISO_XD, B12_P381_ISO_YN, B12_P381_ISO_YD);
// Map scalar to B12_P381
  printf("Mapping the scalar to the curve ...\n");

  p = (ep2_t)malloc(sizeof(ep2_st));
  p->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  p->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  p->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));



  map_scalar_to_curve(p, ttt);

  printf("Finished mapping the scalar to the curve ...\n");

  neg = neg != fp2_sgn0(p->y, e);
  fp2_neg(ttt, p->y);
  dv_copy_cond(p->y[0], ttt[0], RLC_FP_DIGS, neg);
  dv_copy_cond(p->y[1], ttt[1], RLC_FP_DIGS, neg);

// Now apply the isogeny map
//  print_line();
//  printf("The point before applying the isogeny map... \n");
//
//  printf("x coordinate: \n");
//  printf("p->x[0] %" PRIu64 "\n", *(p->x[0] ));
//  printf("p->x[1] %" PRIu64 "\n", *(p->x[0] + 1));
//  printf("p->x[2] %" PRIu64 "\n", *(p->x[0] + 2));
//  printf("p->x[3] %" PRIu64 "\n", *(p->x[0] + 3));
//  printf("p->x[4] %" PRIu64 "\n", *(p->x[0] + 4));
//  printf("p->x[5] %" PRIu64 "\n", *(p->x[0] + 5));
//  printf("y coordinate: \n");
//  printf("p->y[0] %" PRIu64 "\n", *(p->y[0] ));
//  printf("p->y[1] %" PRIu64 "\n", *(p->y[0] + 1));
//  printf("p->y[2] %" PRIu64 "\n", *(p->y[0] + 2));
//  printf("p->y[3] %" PRIu64 "\n", *(p->y[0] + 3));
//  printf("p->y[4] %" PRIu64 "\n", *(p->y[0] + 4));
//  printf("p->y[5] %" PRIu64 "\n", *(p->y[0] + 5));
//  printf("z coordinate: \n");
//  printf("p->z[0] %" PRIu64 "\n", *(p->z[0] ));
//  printf("p->z[1] %" PRIu64 "\n", *(p->z[0] + 1));
//  printf("p->z[2] %" PRIu64 "\n", *(p->z[0] + 2));
//  printf("p->z[3] %" PRIu64 "\n", *(p->z[0] + 3));
//  printf("p->z[4] %" PRIu64 "\n", *(p->z[0] + 4));
//  printf("p->z[5] %" PRIu64 "\n", *(p->z[0] + 5));

  printf("Now applying the isogeny map... \n");

  isogeny_map(p);

  uint64_t px0;
  uint64_t px1;
  uint64_t px2;
  uint64_t px3;
  uint64_t px4;
  uint64_t px5;

  uint64_t py0;
  uint64_t py1;
  uint64_t py2;
  uint64_t py3;
  uint64_t py4;
  uint64_t py5;

  uint64_t pz0;
  uint64_t pz1;
  uint64_t pz2;
  uint64_t pz3;
  uint64_t pz4;
  uint64_t pz5;

  if( sequence == 2){
////////////////////////////////////////
  px0 = 12876831369499511095;
  px1 = 669865624959273240;
  px2 = 5295314185012811767;
  px3 = 10535942465924952507;
  px4 = 6749632078625001325;
  px5 = 544070190095032775;

  py0 = 13807866252442817510;
  py1 = 1206778827755322241;
  py2 = 6227792413039013907;
  py3 = 12409653748090456027;
  py4 = 15923766313813229816;
  py5 = 1280940689572399341;

  pz0 = 14186990084672407827;
  pz1 = 17414337241577503165;
  pz2 = 17737221398210816263;
  pz3 = 5096200064592250870;
  pz4 = 6989538818909868085;
  pz5 = 1219742961965905715;
  }

  if( sequence == 1){
//////////////////////////////////////////
   px0 =  16603095906398444624;
   px1 =  14847369377878545419;
   px2 =  8937774108357643346;
   px3 =  17574689352006813814;
   px4 =  4620856641434282496;
   px5 =  1793872408053411627;
   
   py0 =  17684262036518551128;
   py1 =  18386928879118654222;
   py2 =  13389195836363238096;
   py3 =  6284561072484266232;
   py4 =  5663343310858039123;
   py5 =  1864692639812907776;
   
   pz0 =  10838604725761032207;
   pz1 =  4762092640527260469;
   pz2 =  14549356420920161935;
   pz3 =  5090114536724173654;
   pz4 =  8300404609496668738;
   pz5 =  1618339427510023074;

  }

  if( sequence == 3){
//////////////////////////////////////////
  px0 = 4522175503006271926;
  px1 = 7628860187923640081;
  px2 = 15714645553301507193;
  px3 = 3513625221767549538;
  px4 = 9416525119631435704;
  px5 = 942297724353119737;

  py0 = 7064085492358342813;
  py1 = 3011720167030279849;
  py2 = 6475112925619391838;
  py3 = 17963467974497784593;
  py4 = 9265567426871135047;
  py5 = 1266056669242111252;

  pz0 = 7727439254583007199;
  pz1 = 15108752542132982959;
  pz2 = 12915093228206905201;
  pz3 = 12683266112564391531;
  pz4 = 16970245155421669696;
  pz5 = 585935835826096346;
  }

  printf("Isogeny map applied successfully... \n");
////////////////////////////////////////////////////////////////////
  printf("The resulting point (P) on BLS12-381: \n");
  printf("x coordinate: \n");
  printf("p->x[0] %" PRIu64 "  %" PRIu64 "\n", *(p->x[0]), px0 );
  printf("p->x[1] %" PRIu64 "  %" PRIu64 "\n", *(p->x[0] + 1), px1);
  printf("p->x[2] %" PRIu64 "  %" PRIu64 "\n", *(p->x[0] + 2), px2);
  printf("p->x[3] %" PRIu64 "  %" PRIu64 "\n", *(p->x[0] + 3), px3);
  printf("p->x[4] %" PRIu64 "  %" PRIu64 "\n", *(p->x[0] + 4), px4);
  printf("p->x[5] %" PRIu64 "  %" PRIu64 "\n", *(p->x[0] + 5), px5);
  printf("y coordinate: \n");  
  printf("p->y[0] %" PRIu64 "  %" PRIu64 "\n", *(p->y[0] ), py0);
  printf("p->y[1] %" PRIu64 "  %" PRIu64 "\n", *(p->y[0] + 1), py1);
  printf("p->y[2] %" PRIu64 "  %" PRIu64 "\n", *(p->y[0] + 2), py2);
  printf("p->y[3] %" PRIu64 "  %" PRIu64 "\n", *(p->y[0] + 3), py3);
  printf("p->y[4] %" PRIu64 "  %" PRIu64 "\n", *(p->y[0] + 4), py4);
  printf("p->y[5] %" PRIu64 "  %" PRIu64 "\n", *(p->y[0] + 5), py5);
  printf("z coordinate: \n");  
  printf("p->z[0] %" PRIu64 "  %" PRIu64 "\n", *(p->z[0] ), pz0);
  printf("p->z[1] %" PRIu64 "  %" PRIu64 "\n", *(p->z[0] + 1), pz1);
  printf("p->z[2] %" PRIu64 "  %" PRIu64 "\n", *(p->z[0] + 2), pz2);
  printf("p->z[3] %" PRIu64 "  %" PRIu64 "\n", *(p->z[0] + 3), pz3);
  printf("p->z[4] %" PRIu64 "  %" PRIu64 "\n", *(p->z[0] + 4), pz4);
  printf("p->z[5] %" PRIu64 "  %" PRIu64 "\n", *(p->z[0] + 5), pz5);

  /* compare sign of y to sign of t; fix if necessary */
  printf("Deallocating memory ...\n");

  free(tt->dp);
  free(u->dp);
  free(m->dp);

  free(m);

  free(one.dp);
  free(conv.dp);
  free(r);
  free(tt);
  free(p->x[0]);
  free(p->x[1]);
  free(p->y[0]);
  free(p->y[1]);
  free(p->z[0]);
  free(p->z[1]);
  free(p);
  free(u);
  free(ttt[0]);
  free(ttt[1]);

  return;
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_read_bin(bn_t a, const uint8_t *bin, int len) {
 int i, j; 
 dig_t d = (RLC_DIG / 8); 
 int digs = (len % d == 0 ? len / d : len / d + 1);
 bn_grow(a, digs);
 bn_zero(a);
 a->used = digs;
 printf("\n-------------------\n");
 for (i = 0; i < len; i++) {
  printf("%02x",bin[i]);
 }
 printf("\n-------------------\n");

 for (i = 0; i < digs - 1; i++) {
         d = 0; 
         for (j = (RLC_DIG / 8) - 1; j >= 0; j--) {
                 d = d << 8;
                 d |= bin[len - 1 - (i * (RLC_DIG / 8) + j)];

         }
         a->dp[i] = d;
// printf("a->dp[i] %" PRIu64 " \n", a->dp[i]);


 } 
 d = 0; 
 for (j = (RLC_DIG / 8) - 1; j >= 0; j--) { 
         if ((int)(i * (RLC_DIG / 8) + j) < len) {
                 d = d << 8;
                 d |= bin[len - 1 - (i * (RLC_DIG / 8) + j)];
         }
 }
 a->dp[i] = d;
// printf("a->dp[i] %" PRIu64 " \n", a->dp[i]);
 a->sign = RLC_POS;
 bn_trim(a);


}

__device__
#if INLINE == 0
__noinline__
#endif
void convert_from_hexa(uint8_t *source_array, uint64_t *target_array, int max_index, int block_size){

  for(int index=0; index < max_index; index++){
   int target_array_index = max_index - index - 1;

   target_array[target_array_index] = 0;
   target_array[target_array_index] |= source_array[index*block_size+0];

//   printf("%" PRIu64 "\n", target_array[target_array_index]);

   target_array[target_array_index] = target_array[target_array_index] << 8;
//   printf("%" PRIu64 "\n", target_array[target_array_index]);
   target_array[target_array_index] |= source_array[index*block_size+1];
//   printf("%" PRIu64 "\n", target_array[target_array_index]);

   target_array[target_array_index] = target_array[target_array_index] << 8;
//   printf("%" PRIu64 "\n", target_array[target_array_index]);
   target_array[target_array_index] |= source_array[index*block_size+2];
//   printf("%" PRIu64 "\n", target_array[target_array_index]);

   target_array[target_array_index] = target_array[target_array_index] << 8;
//   printf("%" PRIu64 "\n", target_array[target_array_index]);
   target_array[target_array_index] |= source_array[index*block_size+3];
//   printf("%" PRIu64 "\n", target_array[target_array_index]);

   target_array[target_array_index] = target_array[target_array_index] << 8;
//   printf("%" PRIu64 "\n", target_array[target_array_index]);
   target_array[target_array_index] |= source_array[index*block_size+4];
//   printf("%" PRIu64 "\n", target_array[target_array_index]);

   target_array[target_array_index] = target_array[target_array_index] << 8;
//   printf("%" PRIu64 "\n", target_array[target_array_index]);
   target_array[target_array_index] |= source_array[index*block_size+5];
//   printf("%" PRIu64 "\n", target_array[target_array_index]);

   target_array[target_array_index] = target_array[target_array_index] << 8;
//   printf("%" PRIu64 "\n", target_array[target_array_index]);
   target_array[target_array_index] |= source_array[index*block_size+6];
//   printf("%" PRIu64 "\n", target_array[target_array_index]);

   target_array[target_array_index] = target_array[target_array_index] << 8;
//   printf("%" PRIu64 "\n", target_array[target_array_index]);
   target_array[target_array_index] |= source_array[index*block_size+7];
//   printf("%" PRIu64 "\n", target_array[target_array_index]);
  }

}
__global__
void saxpy(uint8_t *prime, uint64_t *prime2)
{
 bn_t e, e2;
   uint8_t  idx0;
   uint8_t  idx1;

    // mapping of ASCII characters to hex values
   const uint8_t hashmap[] =
   {
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
     0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
     0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
     0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // ........
   };

 uint8_t *msg;

 char message_string_1[513] = "b629a33baa2f71304e6a1f84eed5ab383a23bb055b1442795bcd7ac4fba664c5e178dba9737570dd6ded5f73fd3fbbac25f559e84f2154d8ab0d32442da10a60fc830f54bbfc0b19ba723b0bc4177b96c5fc6aa77cee05ef80163fca2b5b92145c7004beef09abab3d52c6989da26ee0e8c4d63587b8e6127279d5abf4b520becfcd98c2163f82d7f1777d5559fc77ad040bbb8b933780211a5ef359f70788f95773612f69638cae550aed382d68a4be0c194139e7b3069126b2dad1d6e5d8fe5cfc8d5a90c783f1ebab25d095776172a66d9afdb16d7c289ad89c93dda54c7b0cf86991a200ff0e858573796cf396e6ae77470b4dd2d61267f5716de16b199f";
// 15CC3F292D66704A 62687D6E2DCB5913 7C9E20D357539F96 9F51EABD020D64E0 81792D01F15CC248 1D44777B8BAFC9FD ttt[0]
// 147765C676F3B800 6798BA4300F29F76 27CBE052A3D0397E CE0A4A7079E5EFEF 45DECCC08A4147E2 345BA7EC94B37852 ttt[1]

 char message_string_2[513] = "975a7a3edf0c907a8670af92ed36b3a1e94940ed8d4fe0e54592e0a4d6527b5bd6fd4cb9968d760b68be1dc82f576a6a73cc0714e02e353ad6d510f5dfc7f02479abf7ee20e927345cc36b408d3fcd05729fdf18f74f4ad91cc4bd50d3795fe5cfbbfb060689552b39e996fcece89e258b7db611a41c271216af110d493e81e96f9b1aa1696ef41c6573563e84c547de86f18d3ea897956dda7ca5101a47138c906602acf2ebd4cc1c8411b1e4f83825eaacbe54c9ed8a5ae2df3dd04bc77f223e03d78e10ca95d59de0bc047dd33e5a170473d8f70d94bf467ed9684a1ed05cff88779990ba1aa0832005af2a19be3cdd46e68094ed0ba34789c80f24d5f07f";
 char message_string_3[513] = "3d762157e3c4566456bb1a25654b4c17dcc15079d6343a54b76723a2da8580e22fcab914a229f2885d46ce3ac0beb3d1a64a26b1b166acb26b284b25586e1f8d0f3ee175ab69ad80ab1fb623623d1cd750b28c5ba6062d0573ab2b66a83457afce074f5179b8b849fc82d8957121c7bc73b48a64c59e3bd51533769bcb48a61190acf98407ea195ca53ec47b1261227f2fb2652436c094990482889d569b310991c4ae7dcddb375c956a705841a9c5fc87acef7c35f461b4f26d5031b3ce6857f90c78ce931c006f61a3410fef514e1070d07d15cc429d42a86edae22a3650777e94810e873728cc769704660d07a488d3d8efc503fb8c7fdc5de06743fb4936";
 char message_string_4[513] = "b629a33baa2f71304e6a1f84eed5ab383a23bb055b1442795bcd7ac4fba664c5e178dba9737570dd6ded5f73fd3fbbac25f559e84f2154d8ab0d32442da10a60fc830f54bbfc0b19ba723b0bc4177b96c5fc6aa77cee05ef80163fca2b5b92145c7004beef09abab3d52c6989da26ee0e8c4d63587b8e6127279d5abf4b520becfcd98c2163f82d7f1777d5559fc77ad040bbb8b933780211a5ef359f70788f95773612f69638cae550aed382d68a4be0c194139e7b3069126b2dad1d6e5d8fe5cfc8d5a90c783f1ebab25d095776172a66d9afdb16d7c289ad89c93dda54c7b0cf86991a200ff0e858573796cf396e6ae77470b4dd2d61267f5716de16b199f";
 convert_from_hexa(prime,prime2, 6, 8);
 for(int i=0; i < 6; i++){
  shared_prime[i] = prime2[i];
 } 
 msg = (uint8_t*)malloc(256*sizeof(uint8_t));

  e = (bn_t ) malloc(sizeof(bn_st));
  e->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
  e->alloc = RLC_BN_SIZE;
  e->sign = RLC_POS;

  e2 = (bn_t ) malloc(sizeof(bn_st));
  e2->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
  e2->alloc = RLC_BN_SIZE;
  e2->sign = RLC_POS;

////////////////////////////////////////////////////////////
 for(int i = 512; i >= 2; i -= 2){
  int j = 512 - i;
  idx0 = (uint8_t)message_string_1[j];
  idx1 = (uint8_t)message_string_1[j+1];
  int  k = i / 2 - 1;
  msg[k] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
 }
 for(int i = 0; i<256; i++){
  printf("%02x",msg[i]);
 }

  printf("\n");

  bn_read_bin(e, msg, 64);
  bn_read_bin(e2, msg+64, 64);


  signmessage(e,e2, 1);
  return;


////////////////////////////////////////////////////////////
  for(int i = 512; i >= 2; i -= 2){
   int j = 512 - i;
   idx0 = (uint8_t)message_string_2[j];
   idx1 = (uint8_t)message_string_2[j+1];
   int  k = i / 2 - 1;
   msg[k] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
  }

 for(int i = 0; i<256; i++){
  printf("%02x",msg[i]);
 }

  printf("\n");
  bn_read_bin(e, msg, 64);
  bn_read_bin(e2, msg+64, 64);

  signmessage(e,e2, 2);
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
  for(int i = 512; i >= 2; i -= 2){
   int j = 512 - i;
   idx0 = (uint8_t)message_string_3[j];
   idx1 = (uint8_t)message_string_3[j+1];
   int  k = i / 2 - 1;
   msg[k] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
  }
 for(int i = 0; i<256; i++){
  printf("%02x",msg[i]);
 }

  printf("\n");

  bn_read_bin(e, msg, 64);
  bn_read_bin(e2, msg+64, 64);

  signmessage(e,e2, 3);
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
  for(int i = 512; i >= 2; i -= 2){
   int j = 512 - i;
   idx0 = (uint8_t)message_string_4[j];
   idx1 = (uint8_t)message_string_4[j+1];
   int  k = i / 2 - 1;
   msg[k] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
  }
 for(int i = 0; i<256; i++){
  printf("%02x",msg[i]);
 }

  printf("\n");

  bn_read_bin(e, msg, 64);
  bn_read_bin(e2, msg+64, 64);

  signmessage(e,e2, 4);
////////////////////////////////////////////////////////////

  free(msg);
  free(e->dp);
  free(e2->dp);

  free(e);
  free(e2);
}

int main(void)
{
  uint8_t *msg, *d_msg;
  uint64_t *msg2, *d_msg2;
  uint8_t *msg_first, *d_msg_first;

  uint8_t *prime, *cuda_prime;
  uint64_t *prime_2, *cuda_prime_2;

  uint64_t *quotient, *remainder;

  msg = (uint8_t*)malloc(64*sizeof(uint8_t));
  cudaMalloc(&d_msg, 64*sizeof(uint8_t)); 

  msg_first = (uint8_t*)malloc(64*sizeof(uint8_t));
  cudaMalloc(&d_msg_first, 64*sizeof(uint8_t)); 

  msg2 = (uint64_t*)malloc((8+1)*sizeof(uint64_t));
  cudaMalloc(&d_msg2, (8+1)*sizeof(uint64_t)); 

  prime = (uint8_t*)malloc(48*sizeof(uint8_t));
  cudaMalloc(&cuda_prime, 48*sizeof(uint8_t)); 

  prime_2 = (uint64_t*)malloc((6 + 1)*sizeof(uint64_t));
  cudaMalloc(&cuda_prime_2, (6 + 1)*sizeof(uint64_t)); 

  cudaMalloc(&quotient, (6+1)*sizeof(uint64_t)); 
  cudaMalloc(&remainder, (6+1)*sizeof(uint64_t)); 

  prime[47] = 0xAB;
  prime[46] = 0xAA;
  prime[45] = 0xFF;
  prime[44] = 0xFF;
  prime[43] = 0xFF;
  prime[42] = 0xFF;
  prime[41] = 0xFE;
  prime[40] = 0xB9;

  prime[39] = 0xFF;
  prime[38] = 0xFF;
  prime[37] = 0x53;
  prime[36] = 0xB1;
  prime[35] = 0xFE;
  prime[34] = 0xFF;
  prime[33] = 0xAB;
  prime[32] = 0x1E;

  prime[31] = 0x24;
  prime[30] = 0xF6;
  prime[29] = 0xB0;
  prime[28] = 0xF6;
  prime[27] = 0xA0;
  prime[26] = 0xD2;
  prime[25] = 0x30;
  prime[24] = 0x67;

  prime[23] = 0xBF;
  prime[22] = 0x12;
  prime[21] = 0x85;
  prime[20] = 0xF3;
  prime[19] = 0x84;
  prime[18] = 0x4B;
  prime[17] = 0x77;
  prime[16] = 0x64;

  prime[15] = 0xD7;
  prime[14] = 0xAC;
  prime[13] = 0x4B;
  prime[12] = 0x43;
  prime[11] = 0xB6;
  prime[10] = 0xA7;
  prime[9] = 0x1B;
  prime[8] = 0x4B;
  prime[7] = 0x9A;
  prime[6] = 0xE6;
  prime[5] = 0x7F;
  prime[4] = 0x39;
  prime[3] = 0xEA;
  prime[2] = 0x11;
  prime[1] = 0x01;
  prime[0] = 0x1A;

  cudaMemcpy(d_msg, msg, 64*sizeof(uint8_t), cudaMemcpyHostToDevice);
  cudaMemcpy(d_msg_first, msg_first, 64*sizeof(uint8_t), cudaMemcpyHostToDevice);
  cudaMemcpy(cuda_prime, prime, 48*sizeof(uint8_t), cudaMemcpyHostToDevice);

  size_t deviceLimit;
  gpuErrChk(cudaDeviceGetLimit(&deviceLimit, cudaLimitStackSize));
//  printf("Original Device stack size: %d\n", (int) deviceLimit);
    
  cudaDeviceSetLimit(cudaLimitMallocHeapSize, 128*1024*1024);
  gpuErrChk(cudaDeviceSetLimit(cudaLimitStackSize, 1024));
  gpuErrChk(cudaDeviceGetLimit(&deviceLimit, cudaLimitStackSize));

  cudaEvent_t start, stop;
  float elapsedTime;

  cudaEventCreate(&start);
  cudaEventRecord(start,0);

  saxpy<<<NBLOCKS, NTHREADS>>>(cuda_prime, cuda_prime_2);


  cudaEventCreate(&stop);
  cudaEventRecord(stop,0);
  cudaEventSynchronize(stop);

  cudaEventElapsedTime(&elapsedTime, start,stop);
  printf("Elapsed time : %f ms\n" ,elapsedTime);

  cudaMemcpy(msg2, d_msg2, 8*sizeof(uint64_t), cudaMemcpyDeviceToHost);
  cudaMemcpy(prime_2, cuda_prime_2, 6*sizeof(uint64_t), cudaMemcpyDeviceToHost);
// h = SHA-256(msg) --> 8 uint64_t conversion done

  cudaFree(cuda_prime);
  cudaFree(d_msg);
  cudaFree(d_msg2);
  free(prime);
  free(msg);
  free(msg2);
  cudaDeviceReset();
}
