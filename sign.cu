// compile with nime nvcc -o sign sign.cu  -rdc=false -Xptxas -v  -O0  -lineinfo --ptxas-options=-O0
// /usr/bin/c++ -DSODIUM_STATIC -I/home/c/bls-signatures/src -I/home/c/bls-signatures/build/_deps/relic-src/include -I/home/c/bls-signatures/build/_deps/relic-build/include -I/home/c/bls-signatures/build/_deps/sodium-src/libsodium/src/libsodium/include -O3 -DNDEBUG -fPIE -std=gnu++17 -MD -MT main.cpp.o -MF main.cpp.o.d -o main.cpp.o -c main.cpp; /usr/bin/c++ -O3 -DNDEBUG main.cpp.o -o runmain  /home/c/bls-signatures/build/src/libbls.a /home/c/bls-signatures/build/_deps/relic-build/lib/librelic_s.a /usr/lib/x86_64-linux-gnu/libgmp.so -lrt -lpthread -lm /home/c/bls-signatures/build/_deps/sodium-build/libsodium.a
//  sudo apt-get purge nvidia*
//  sudo apt-get autoremove
//  sudo reboot
//  lsmod | grep nvidia.drm
//  sudo sh cuda_12.0.0_525.60.13_linux.run
//  sudo /usr/local/NVIDIA-Nsight-Compute-2022.4/ncu --call-stack -f --set detailed -k runbls -o res ./sign --metrics gpu__time_duration.sum

#include <stdio.h>
#include <malloc.h>
#include <time.h>

#include <inttypes.h>
#include <stdint.h>
#include<string.h>
#include <stdarg.h>
#include <ctype.h>


//#define NBLOCKS 1
#define NTHREADS 1

#define RLC_TERMS               16

#define EP_ENDOM
#define EP_PRECO
#define rlc_align               /* empty*/



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
#define JACOB    3

#define EP_ADD PROJC

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
/**
 * Constant used to indicate that there's some room left in the storage of
 * prime field elements. This can be used to avoid carries.
 */
#if ((FP_PRIME % WSIZE) != 0) && ((FP_PRIME % WSIZE) <= (WSIZE - 2))
#if ((2 * FP_PRIME % WSIZE) != 0) && ((2 * FP_PRIME % WSIZE) <= (WSIZE - 2))
#define RLC_FP_ROOM
#else
#undef RLC_FP_ROOM
#endif
#else
#undef RLC_FP_ROOM
#endif

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
typedef dv_t dv2_t[2];
typedef dv2_t dv6_t[3];
typedef dv2_t dv4_t[2];
typedef dv6_t dv12_t[2];



#define RLC_PAD(A)              (0)
/**
 * Represents a prime field element with automatic memory allocation.
 */
typedef dig_t fp_st[RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)];

typedef struct {
        /** The first coordinate. */
        fp_st x;
        /** The second coordinate. */
        fp_st y;
        /** The third coordinate (projective representation). */
        fp_st z;
        /** Flag to indicate the coordinate system of this point. */
        int coord;
} ep_st;
typedef ep_st *ep_t;

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
typedef fp2_t fp6_t[3];
typedef fp6_t fp12_t[2];
typedef fp2_t fp4_t[2];


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
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_new(fp2_t p) {
  p[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[0][0] = 0;
  p[0][1] = 0;
  p[0][2] = 0;
  p[0][3] = 0;
  p[0][4] = 0;
  p[0][5] = 0;
  p[1][0] = 0;
  p[1][1] = 0;
  p[1][2] = 0;
  p[1][3] = 0;
  p[1][4] = 0;
  p[1][5] = 0;
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_new(fp6_t p) {
 fp2_new(p[0]); 
 fp2_new(p[1]); 
 fp2_new(p[2]); 
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_new(fp12_t p) {
  p[0][0][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[0][0][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[0][1][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[0][1][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[0][2][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[0][2][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  p[1][0][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[1][0][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[1][1][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[1][1][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[1][2][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p[1][2][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp4_new(fp4_t p) {
 fp2_new(p[0]); 
 fp2_new(p[1]); 
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_free(fp2_t p) {
 free(p[0]);
 free(p[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp4_free(fp4_t p) {
 fp2_free(p[0]);
 fp2_free(p[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_free(fp6_t p) {
 fp2_free(p[0]); 
 fp2_free(p[1]); 
 fp2_free(p[2]);                                            \
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_free(fp12_t p) {
 fp6_free(p[0]); 
 fp6_free(p[1]); 
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_null(fp2_t p) {
 /**/ 
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
// clock_t start = clock();

        for (i = 0; i < RLC_FP_DIGS; i++, a++, b++, c++) {
                r0 = (*a) + (*b);
                c0 = (r0 < (*a));
                r1 = r0 + carry;
                c1 = (r1 < r0);
                carry = c0 | c1;
                (*c) = r1;
        }
// clock_t stop = clock();
// printf("fp_addn_low took: %d cycles \n",(int)(stop - start));
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
	if (norm < (int)(RLC_DIG - 1)) {
		norm = (RLC_DIG - 1) - norm;
		carry = bn_lshb_low(a, a, sa, norm);
		if (carry) {
			a[sa++] = carry;
		}
		carry = bn_lshb_low(b, b, sb, norm);
		if (carry) {
			b[sb++] = carry;
		}
	} else {
		norm = 0;
	}
	n = sa - 1;
	t = sb - 1;
	/* Shift y so that the most significant digit of y is aligned with the
	 * most significant digit of x. */
	dv_lshd(b, b, sb + (n - t), (n - t));

	/* Find the most significant digit of the quotient. */
	while (dv_cmp(a, b, sa) != RLC_LT) {
		c[n - t]++;
		bn_subn_low(a, a, b, sa);
	}

	/* Shift y back. */
	dv_rshd(b, b, sb + (n - t), (n - t));

	/* Find the remaining digits. */
	for (i = n; i >= (t + 1); i--) {
		dig_t tmp;
		if (i > sa) {
			continue;
		}
		if (a[i] == b[t]) {
			c[i - t - 1] = RLC_MASK(RLC_DIG);
		} else {
			RLC_DIV_DIG(c[i - t - 1], tmp, a[i], a[i - 1], b[t]);
		}
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
		if (carry) {
			sd = sb + (i - t - 1);
			carry = bn_addn_low(a + (i - t - 1), a + (i - t - 1), b, sb);
			carry = bn_add1_low(a + sd, a + sd, carry, sa - sd);
			c[i - t - 1]--;
		}
	}
	/* Remainder should be not be longer than the divisor. */
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

        x = (bn_t) malloc(sizeof(bn_st));
        x->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
        x->alloc = RLC_BN_SIZE;
        x->sign = RLC_POS;

        q = (bn_t) malloc(sizeof(bn_st));
        q->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
        q->alloc = RLC_BN_SIZE;
        y = (bn_t) malloc(sizeof(bn_st));
        y->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
        y->alloc = RLC_BN_SIZE;
        y->sign = RLC_POS;

        r = (bn_t) malloc(sizeof(bn_st));
        r->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
        r->alloc = RLC_BN_SIZE;
        r->sign = RLC_POS;

        bn_new(x);
        bn_new(q);
        bn_new(y);
        bn_new(r);


        /* If |a| < |b|, we're done. */
        if (bn_cmp_abs(a, b) == RLC_LT) {
                if (bn_sign(a) == bn_sign(b)) {
                        if (c != NULL) {
                                bn_zero(c);
                        }
                        if (d != NULL) {
                                bn_copy(d, a);
                        }
                } else {
                        if (c != NULL) {
                                bn_set_dig(c, 1);
                                bn_neg(c, c);
                        }
                        if (d != NULL) {
                                bn_add(d, a, b);
                        }
                }
                return;
        }

                /* Be conservative about space for scratch memory, many attempts to
                 * optimize these had invalid reads. */

                bn_new_size(x, a->used + 1);
                bn_new_size(q, a->used + 1);
                bn_new_size(y, a->used + 1);
                bn_new_size(r, a->used + 1);

                bn_zero(q);
                bn_zero(r);
                bn_abs(x, a);
                bn_abs(y, b);

                /* Find the sign. */
                sign = (a->sign == b->sign ? RLC_POS : RLC_NEG);

                bn_divn_low(q->dp, r->dp, x->dp, a->used, y->dp, b->used);

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

        dv_copy(t2, a, 2 * RLC_FP_DIGS);
        dv_copy(t3, shared_prime, RLC_FP_DIGS);
// clock_t stop = clock();

// itt a t/knek tul kicsi hely van foglalva es tul fogjak cimezni egymast....

// start = clock();
        clock_t start = clock();

        bn_divn_low(t0, t1, t2, 2 * RLC_FP_DIGS, t3, RLC_FP_DIGS);

        clock_t stop = clock();
// printf("bn_divn_low took: %d cycles \n",(int)(stop - start));

        fp_copy(c, t1);
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
        bn_sqra_low(t + 2 * i, a + i, 1);
        fp_rdc_basic(c, t);
        free(t);
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
void fp_mul_basic(fp_t c, const fp_t a, const fp_t b) {
        int i;
        dv_t t;
        dig_t carry;

        clock_t start = clock();

//        dv_null(t);
        /* We need a temporary variable so that c can be a or b. */
//        dv_new(t);
        t = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));

        dv_zero(t, 2 * RLC_FP_DIGS);
        for (i = 0; i < RLC_FP_DIGS; i++) {
                carry = fp_mula_low(t + i, b, *(a + i));
                *(t + i + RLC_FP_DIGS) = carry;
        }
        fp_rdc_basic(c, t);
        free(t);
        clock_t stop = clock();
//      printf("fp_mul_basic took: %d cycles \n",(int)(stop - start));
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
// printf(" bn_bits(b): %d \n",l);
        fp_copy(r, a);
        if(r == NULL){
         printf("r has problems...\n");
        }

        for (i = l - 2; i >= 0; i--) {
         fp_sqr_basic(r, r);
        if(r == NULL){
         printf("r has problems...\n");
        }
         if (bn_get_bit(b, i)) {
          fp_mul_basic(r, r, a);
         }
        }
        if(r == NULL){
         printf("r has problems...\n");
        }
        if (bn_sign(b) == RLC_NEG) {
         fp_inv_exgcd(c, r);
        } else {
        if(r == NULL){
         printf("r has problems...\n");
        }
         fp_copy(c, r);
        }

        free(r);
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

        if(c == NULL){
         printf(" undefined pointer in fp_dblm_low... \n");
        }
        carry = 0;
        for (i = 0; i < RLC_FP_DIGS; i++, a++) {
                r0 = (*a) + (*a);
                c0 = (r0 < (*a));
                r1 = r0 + carry;
                c1 = (r1 < r0);
                carry = c0 | c1;

// printf(" r1 %" PRIu64 " \n",r1);
// printf(" r0 %" PRIu64 " \n",r0);
// printf(" c1 %" PRIu64 " \n",c1);
// printf(" c0 %" PRIu64 " \n",c0);
// printf("i: %d fp_dblm_low 7. \n",i);
// printf(" c[i] %" PRIu64 " \n",c[i]);
// printf("i: %d fp_dblm_low 7. \n",i);

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
void fp2_sqr(fp2_t c, fp2_t a) {
 clock_t start = clock();
 fp2_sqr_basic(c,a);
 clock_t stop = clock();
// printf("fp2_sqr_basic took: %d cycles \n",(int)(stop - start));
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
void ep_print(const ep_t p) {
        fp_print(p->x);
        fp_print(p->y);
        fp_print(p->z);
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
void fp12_print(fp12_t a) {
        fp_print(a[0][0][0]);
        fp_print(a[0][0][1]);
        fp_print(a[0][1][0]);
        fp_print(a[0][1][1]);
        fp_print(a[0][2][0]);
        fp_print(a[0][2][1]);
        fp_print(a[1][0][0]);
        fp_print(a[1][0][1]);
        fp_print(a[1][1][0]);
        fp_print(a[1][1][1]);
        fp_print(a[1][2][0]);
        fp_print(a[1][2][1]);
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
void fp2_mul(fp2_t c, fp2_t a, fp2_t b) {
 fp2_mul_basic(c,a,b);
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
void fp2_add(fp2_t c, fp2_t a,  fp2_t b) {
 fp2_add_basic(c,a,b);
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


        t0 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
        t1 = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
		/* t0 = a_0^2, t1 = a_1^2. */
		fp_sqr(t0, a[0]);
		fp_sqr(t1, a[1]);

		/* t1 = 1/(a_0^2 + a_1^2). */
#ifndef FP_QNRES
		if (fp_prime_get_qnr() != -1) {
			if (fp_prime_get_qnr() == -2) {
				fp_dbl(t1, t1);

				fp_add(t0, t0, t1);

			} else {
				if (fp_prime_get_qnr() < 0) {
					fp_mul_dig(t1, t1, -fp_prime_get_qnr());

					fp_add(t0, t0, t1);

				} else {
					fp_mul_dig(t1, t1, fp_prime_get_qnr());

					fp_sub(t0, t0, t1);
				}
			}
		} else {

			fp_add(t0, t0, t1);

		}
#else
		fp_add(t0, t0, t1);
#endif
		fp_inv(t1, t0);

		/* c_0 = a_0/(a_0^2 + a_1^2). */
		fp_mul(c[0], a[0], t1);
		/* c_1 = - a_1/(a_0^2 + a_1^2). */
		fp_mul(c[1], a[1], t1);
		fp_neg(c[1], c[1]);
 free(t0);
 free(t1);

 
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

        fp_prime_back(k, t[0]);
        const int t_0_neg = bn_get_bit(k, 0);

        fp_prime_back(k, t[1]);
        const int t_1_neg = bn_get_bit(k, 0);

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
    fp_set_dig(t0, -fp_prime_get_qnr());
    fp_inv(t0, t0);
    fp_mul(t0, t0, a[0]);
   }
#endif
  fp_neg(t0, t0);
  fp_zero(c[0]);
  if (!fp_srt(c[1], t0)) {
   /* should never happen! */
   printf("Problem in squaring field elements...\n");
  }
  }
 } 
 else {
  /* t0 = a[0]^2 - i^2 * a[1]^2 */
//   printf("a0 a1:\n");
//   fp_print(a[0]);
//   fp_print(a[1]);
  fp_sqr(t0, a[0]);
  fp_sqr(t1, a[1]);
//   printf("a0 a1^2:\n");
//   fp_print(t0);
//   fp_print(t1);
 
  for (int i = -1; i > fp_prime_get_qnr(); i--) {
   fp_add(t0, t0, t1);
  }
 
//   printf("a[0]^2 - i^2 * a[1]^2:\n");
//   fp_print(t0);
//
  fp_add(t0, t0, t1);
 
//   fp_print(t0);
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
//  printf("r: %d\n",r);
  return r;
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
 if (bn_is_zero(t)) {
  fp_zero(a);
 } 
 else {
  if (t->used == 1) {
   fp_prime_conv_dig(a, t->dp[0]);
   if (bn_sign(t) == RLC_NEG) {
    fp_neg(a, a);
   }
  } 
  else {
   fp_prime_conv(a, t);
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
// printf("Normalizing the coordinates...\n");
 if (p->coord != BASIC) {            
  ep2_norm(p, p);                     
 }                                     
 iso2_t coeffs = shared_coeffs;
// printf("Evaluating the polynomial...\n");
 /* numerators */                             
 fp2_eval(t0, p->x, coeffs->xn, coeffs->deg_xn);
// printf("t0: \n");
// fp2_print(t0);
 fp2_eval(t1, p->x, coeffs->yn, coeffs->deg_yn);
// printf("t1: \n");
// fp2_print(t1);
 /* denominators */                           
 fp2_eval(t2, p->x, coeffs->yd, coeffs->deg_yd);
// printf("t2: \n");
// fp2_print(t2);
 fp2_eval(t3, p->x, coeffs->xd, coeffs->deg_xd);
// printf("t3: \n");
// fp2_print(t3);
 /* normalize if necessary */  

/* Y = Ny * Dx * Z^2. */                                                                                        
 fp2_mul_basic(p->y, p->y, t1);
// printf("1. p->y: \n");
// fp2_print(p->y);
 fp2_mul_basic(p->y, p->y, t3);
// printf("2. p->y: \n");
// fp2_print(p->y);
 /* Z = Dx * Dy, t1 = Z^2. */                                                                            \
 fp2_mul_basic(p->z, t2, t3);
// printf("p->z: \n");
// fp2_print(p->z);
 fp2_sqr_basic(t1, p->z);
 fp2_mul_basic(p->y, p->y, t1);
 /* X = Nx * Dy * Z. */                                                                                          \
 fp2_mul_basic(p->x, t0, t2);
// printf("1. p->x: \n");
// fp2_print(p->x);
 fp2_mul_basic(p->x, p->x, p->z);
// printf("2. p->x: \n");
// fp2_print(p->x);
 p->coord = PROJC;

// Itt nincs felszabadítva a memória...
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
// printf("now precomputing the isomap constants...\n");
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
// printf("Computing the SSWU map ...\n");

// printf("t: \n");
// fp2_print(t);
 fp2_sqr_basic(t0, t);
// printf("t^2: \n");
// fp2_print(t0);

// printf("u:  \n");
// fp2_print(u);
 fp2_mul_basic(t0, t0, u);  /* t0 = u * t^2 */
// printf("u * t^2: \n");
// fp2_print(t0);
 fp2_sqr_basic(t1, t0);     /* t1 = u^2 * t^4 */
// printf("u^2 * t^4: \n");
// fp2_print(t1);
 fp2_add_basic(t2, t1, t0); /* t2 = u^2 * t^4 + u * t^2 */ 
// printf("u^2 * t^4 + u * t^2: \n");
// fp2_print(t2);
// printf("Computing the SSWU map finished...\n");

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
// printf("compute x1, g(x1)... \n");
// printf("mBoverA: \n");
// fp2_print(mBoverA);
 fp2_mul_basic(p->x, t2, mBoverA); /* -B / A * (1 + 1 / (u^2 * t^4 + u * t^2)) */
// printf("p->x: \n");
// fp2_print(p->x);
 fp2_sqr_basic(p->y, p->x);        /* x^2 */                                    
 fp2_add_basic(p->y, p->y, a);     /* x^2 + a */                               
 fp2_mul_basic(p->y, p->y, p->x);  /* x^3 + a x */                            
 fp2_add_basic(p->y, p->y, b);     /* x^3 + a x + b */                       
// printf("x^3 + a x + b: \n");
// fp2_print(p->y);
// printf("compute x1, g(x1) finished... \n");
 /* compute x2, g(x2) */                                            
// printf("compute x2, g(x2) ... \n");
 fp2_mul_basic(t2, t0, p->x); /* t2 = u * t^2 * x1 */                    
 fp2_mul_basic(t1, t0, t1);   /* t1 = u^3 * t^6 */                      
 fp2_mul_basic(t3, t1, p->y); /* t5 = g(t2) = u^3 * t^6 * g(p->x) */   
// printf("compute x2, g(x2) finished... \n");
//  /* XXX(rsw)                                                               */   
//  /* This should be done in constant time and without computing 2 sqrts.    */  
//  /* Avoiding a second sqrt relies on knowing the 2-adicity of the modulus. */ 
  if (!fp2_srt(p->y, p->y)) {                                                 
          /* try x2, g(x2) */                                                
//          printf("--- second sqrt--- \n");
//          printf("(p->y)^(1/2): \n");               
//          fp2_print(p->y); 
          fp2_mul_basic(t2, t0, p->x); /* t2 = u * t^2 * x1 */
//          printf("t2: \n");               
//          fp2_print(t2); 
          fp2_copy(p->x, t2);                                               
          fp2_sqr_basic(t1, t); /* */ 
//          printf("t^2: \n");               
//          fp2_print(t1); 
          fp2_mul_basic(t1, t, t1); /* t1 = t^3 */    
//          printf("t^3: \n");               
//          fp2_print(t1); 
          fp2_sqr_basic(t0, u);  /* t0  */           
          fp2_mul_basic(t0, t0, u);  /* t0 = u^3 */   
//          printf("u^3: \n");               
//          fp2_print(t0); 
          fp2_srt(t0, t0);     /* t3 = sqrt(u^3) */           
//          printf("u^(3/2): \n");               
//          fp2_print(t0); 
          fp2_mul_basic(p->y, p->y, t0);  /* t0 = u * t^2 */         
//          printf("1. p->y: \n");
//          fp2_print(p->y);
          fp2_srt(p->y, p->y);     /* t3 = -u */          
//          printf("2. p->y: \n");
//          fp2_print(p->y);
          fp2_mul_basic(p->y, p->y, t1); /* t5 = g(t2) = u^3 * t^6 * g(p->x) */     
//          printf("3. p->y: \n");
//          fp2_print(p->y);
//          if (!fp2_srt(p->y, t3)) {                                        
//                  printf("+++++++++ Error +++++++++ \n");
//                  printf("!fp2_srt(p->y, t3) in MAP calculation...\n");
//                  printf("++++++++ !Error! ++++++++++ \n");
//          }                                                              
  }    
  fp2_set_dig(p->z, 1);
  p->coord = BASIC;  
//  printf("p->y: \n");
//  fp2_print(p->y);
//  printf("p->z: \n");
//  fp2_print(p->z);
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

//        printf("Done reading a and b...\n");
        /* isogeny map coeffs */
        shared_coeffs->deg_xn = ep2_curve_get_coeffs(shared_coeffs->xn, xn_str);
        shared_coeffs->deg_xd = ep2_curve_get_coeffs(shared_coeffs->xd, xd_str);
        shared_coeffs->deg_yn = ep2_curve_get_coeffs(shared_coeffs->yn, yn_str);
        shared_coeffs->deg_yd = ep2_curve_get_coeffs(shared_coeffs->yd, yd_str);
//        printf("Leaving ep2_curve_set_ctmap a and b...\n");
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
void ep2_print(ep2_t p) {
        fp2_print(p->x);
        fp2_print(p->y);
        fp2_print(p->z);
}



__device__
#if INLINE == 0
__noinline__
#endif
void signmessage(bn_t e, bn_t e2, int sequence,ep2_t p){
 uint64_t carry;
 int neg;
 bn_t u, m, tt;
 fp_t r;
 fp2_t ttt;
 bn_st conv;
 bn_st one;

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

  bn_lsh(&one, &one, RLC_FP_DIGS * RLC_DIG);

// Calculate 1 mod p
  bn_mod_basic(&one, &one, m);
  r = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  fp_add_basic(r, one.dp, one.dp);

  tt = (bn_t ) malloc(sizeof(bn_st));
  tt->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
  tt->alloc = RLC_BN_SIZE;
  tt->sign = RLC_POS;
  bn_set_dig(u, RLC_FP_DIGS);
  bn_lsh(u, u, RLC_DIG_LOG);

  fp_exp_basic(conv.dp, r, u);
  conv.used = RLC_FP_DIGS;
  bn_trim(&(conv));

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


  fp_prime_conv(ttt[0], e);
  fp_prime_conv(ttt[1], e2);
//  printf("message: \n");
//  fp2_print(ttt);
//  printf("bID %d thID: %d ttt[0] %" PRIu64 " ttt[1] %" PRIu64 "\n",blockIdx.x, threadIdx.x,  *ttt[0], *ttt[1]);
//  fp_print(ttt[0]);
//  fp_print(ttt[1]);

/////////////////////////////////////////////////////////////////////////
  /* sign of t */                                                                
  neg = fp2_sgn0(ttt, e);
//  printf("Setting the isogeny map ...\n");
// Calculate parameters for the curve isogeny
  ep2_curve_set_ctmap(B12_P381_ISO_A0, B12_P381_ISO_A1, B12_P381_ISO_B0, B12_P381_ISO_B1, B12_P381_ISO_XN, B12_P381_ISO_XD, B12_P381_ISO_YN, B12_P381_ISO_YD);
// Map scalar to B12_P381
//  printf("Mapping the scalar to the curve ...\n");

  map_scalar_to_curve(p, ttt);

//  printf("Finished mapping the scalar to the curve ...\n");

  neg = neg != fp2_sgn0(p->y, e);
//  printf("1. PT->y: \n");
//  fp2_print(p->y);
  fp2_neg(ttt, p->y);
//  printf("2. PT->y: \n");
//  fp2_print(p->y);
  dv_copy_cond(p->y[0], ttt[0], RLC_FP_DIGS, neg);
//  printf("3. PT->y: \n");
//  fp2_print(p->y);
  dv_copy_cond(p->y[1], ttt[1], RLC_FP_DIGS, neg);
//  printf("4. PT->y: \n");
//  fp2_print(p->y);

// Now apply the isogeny map

//  printf("Now applying the isogeny map... \n");

  isogeny_map(p);

//  printf("Isogeny map applied successfully... \n");
////////////////////////////////////////////////////////////////////
//  printf("\n The result (P) on BLS12-381: (%d) \n", blockIdx.x);
//  ep2_print(p);
//  printf("Deallocating memory ...\n");

  free(tt->dp);
  free(u->dp);
  free(m->dp);

  free(m);

  free(one.dp);
  free(conv.dp);
  free(r);
  free(tt);
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
 for (i = 0; i < digs - 1; i++) {
         d = 0; 
         for (j = (RLC_DIG / 8) - 1; j >= 0; j--) {
                 d = d << 8;
                 d |= bin[len - 1 - (i * (RLC_DIG / 8) + j)];

         }
         a->dp[i] = d;
 } 
 d = 0; 
 for (j = (RLC_DIG / 8) - 1; j >= 0; j--) { 
         if ((int)(i * (RLC_DIG / 8) + j) < len) {
                 d = d << 8;
                 d |= bin[len - 1 - (i * (RLC_DIG / 8) + j)];
         }
 }
 a->dp[i] = d;
 a->sign = RLC_POS;
 bn_trim(a);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_dbl_basic(fp2_t c, fp2_t a) {
  /* 2 * (a_0 + a_1 * u) = 2 * a_0 + 2 * a_1 * u. */
  fp_dbl(c[0], a[0]);
  fp_dbl(c[1], a[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_dbl(fp2_t c, fp2_t a) {
 fp2_dbl_basic(c,a);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_sub_basic(fp2_t c, fp2_t a, fp2_t b) {
  fp_sub(c[0], a[0], b[0]);
  fp_sub(c[1], a[1], b[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_sub(fp2_t c, fp2_t a, fp2_t b) {
 fp2_sub_basic(c,a,b);
}

__device__
#if INLINE == 0
__noinline__
#endif
static void ep2_dbl_basic_imp(ep2_t r, fp2_t s, ep2_t p) {
        fp2_t t0, t1, t2;
        fp2_t zero;

 t0[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t0[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t2[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t2[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 zero[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 zero[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));


                /* t0 = 1/(2 * y1). */
                fp2_dbl_basic(t0, p->y);
                fp2_inv(t0, t0);

                /* t1 = 3 * x1^2 + a. */
                fp2_sqr_basic(t1, p->x);
                fp2_copy(t2, t1);
                fp2_dbl_basic(t1, t1);
                fp2_add_basic(t1, t1, t2);

                fp_zero(zero[0]);
                fp_zero(zero[1]);
                fp2_add_basic(t1, t1, zero);
                free(zero[0]);
                free(zero[1]);

                /* t1 = (3 * x1^2 + a)/(2 * y1). */
                fp2_mul_basic(t1, t1, t0);

                if (s != NULL) {
                        fp2_copy(s, t1);
                }

                /* t2 = t1^2. */
                fp2_sqr_basic(t2, t1);

                /* x3 = t1^2 - 2 * x1. */
                fp2_dbl_basic(t0, p->x);
                fp2_sub_basic(t0, t2, t0);

                /* y3 = t1 * (x1 - x3) - y1. */
                fp2_sub_basic(t2, p->x, t0);
               fp2_mul_basic(t1, t1, t2);

                fp2_sub_basic(r->y, t1, p->y);

                fp2_copy(r->x, t0);
                fp2_copy(r->z, p->z);

                r->coord = BASIC;
                return;
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep2_dbl_slp_basic(ep2_t r, fp2_t s, ep2_t p) {
        if (ep2_is_infty(p)) {
                ep2_set_infty(r);
                return;
        }

        ep2_dbl_basic_imp(r, s, p);
}

__device__
#if INLINE == 0
__noinline__
#endif
static void ep2_add_basic_imp(ep2_t r, fp2_t s, ep2_t p, ep2_t q) {
        fp2_t t0, t1, t2;


 t0[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t0[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t2[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t2[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
                /* t0 = x2 - x1. */
                fp2_sub_basic(t0, q->x, p->x);
                /* t1 = y2 - y1. */
                fp2_sub_basic(t1, q->y, p->y);

                /* If t0 is zero. */
                if (fp2_is_zero(t0)) {
                        if (fp2_is_zero(t1)) {
                                /* If t1 is zero, q = p, should have doubled. */
                                ep2_dbl_slp_basic(r, s, p);
                        } else {
                                /* If t1 is not zero and t0 is zero, q = -p and r = infty. */
                                ep2_set_infty(r);
                        }
                } else {
                        /* t2 = 1/(x2 - x1). */
                        fp2_inv(t2, t0);
                        /* t2 = lambda = (y2 - y1)/(x2 - x1). */
                        fp2_mul_basic(t2, t1, t2);

                        /* x3 = lambda^2 - x2 - x1. */
                        fp2_sqr_basic(t1, t2);
                        fp2_sub_basic(t0, t1, p->x);
                        fp2_sub_basic(t0, t0, q->x);

                        /* y3 = lambda * (x1 - x3) - y1. */
                        fp2_sub_basic(t1, p->x, t0);
                        fp2_mul_basic(t1, t2, t1);
                        fp2_sub_basic(r->y, t1, p->y);

                        fp2_copy(r->x, t0);
                        fp2_copy(r->z, p->z);
                        if (s != NULL) {
                                fp2_copy(s, t2);
                        }

                        r->coord = BASIC;
 }
//                fp2_free(t0);
//                fp2_free(t1);
//                fp2_free(t2);
 return;
}

__device__
#if INLINE == 0
__noinline__
#endif
static void ep2_dbl_projc_imp(ep2_t r, ep2_t p) {
	fp2_t t0, t1, t2, t3, t4, t5;



//		if (ep_curve_opt_a() == RLC_ZERO) {

 t0[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t0[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t2[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t2[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t3[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t3[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t4[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t4[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t5[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t5[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

			fp2_sqr(t0, p->x);
			fp2_add(t2, t0, t0);
			fp2_add(t0, t2, t0);

			fp2_sqr(t3, p->y);
			fp2_mul(t1, t3, p->x);
			fp2_add(t1, t1, t1);
			fp2_add(t1, t1, t1);
			fp2_sqr(r->x, t0);
			fp2_add(t2, t1, t1);
			fp2_sub(r->x, r->x, t2);
			fp2_mul(r->z, p->z, p->y);
			fp2_add(r->z, r->z, r->z);
			fp2_add(t3, t3, t3);

			fp2_sqr(t3, t3);
			fp2_add(t3, t3, t3);
			fp2_sub(t1, t1, r->x);
			fp2_mul(r->y, t0, t1);
			fp2_sub(r->y, r->y, t3);
//		} else {
//			/* dbl-2007-bl formulas: 1M + 8S + 1*a + 10add + 1*8 + 2*2 + 1*3 */
//			/* http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl */
//
//			/* t0 = x1^2, t1 = y1^2, t2 = y1^4. */
//			fp2_sqr(t0, p->x);
//			fp2_sqr(t1, p->y);
//			fp2_sqr(t2, t1);
//
//			if (p->coord != BASIC) {
//				/* t3 = z1^2. */
//				fp2_sqr(t3, p->z);
//
//				if (ep_curve_get_a() == RLC_ZERO) {
//					/* z3 = 2 * y1 * z1. */
//					fp2_mul(r->z, p->y, p->z);
//					fp2_dbl(r->z, r->z);
//				} else {
//					/* z3 = (y1 + z1)^2 - y1^2 - z1^2. */
//					fp2_add(r->z, p->y, p->z);
//					fp2_sqr(r->z, r->z);
//					fp2_sub(r->z, r->z, t1);
//					fp2_sub(r->z, r->z, t3);
//				}
//			} else {
//				/* z3 = 2 * y1. */
//				fp2_dbl(r->z, p->y);
//			}
//
//			/* t4 = S = 2*((x1 + y1^2)^2 - x1^2 - y1^4). */
//			fp2_add(t4, p->x, t1);
//			fp2_sqr(t4, t4);
//			fp2_sub(t4, t4, t0);
//			fp2_sub(t4, t4, t2);
//			fp2_dbl(t4, t4);
//
//			/* t5 = M = 3 * x1^2 + a * z1^4. */
//			fp2_dbl(t5, t0);
//			fp2_add(t5, t5, t0);
//			if (p->coord != BASIC) {
//				fp2_sqr(t3, t3);
//				fp2_mul(t1, t3, ep2_curve_get_a());
//				fp2_add(t5, t5, t1);
//			} else {
//				fp2_add(t5, t5, ep2_curve_get_a());
//			}
//
//			/* x3 = T = M^2 - 2 * S. */
//			fp2_sqr(r->x, t5);
//			fp2_dbl(t1, t4);
//			fp2_sub(r->x, r->x, t1);
//
//			/* y3 = M * (S - T) - 8 * y1^4. */
//			fp2_dbl(t2, t2);
//			fp2_dbl(t2, t2);
//			fp2_dbl(t2, t2);
//			fp2_sub(t4, t4, r->x);
//			fp2_mul(t5, t5, t4);
//			fp2_sub(r->y, t5, t2);
//		}

		r->coord = PROJC;
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep2_dbl_projc(ep2_t r, ep2_t p) {
	if (ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	ep2_dbl_projc_imp(r, p);
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep2_dbl(ep2_t r, ep2_t p) {
	ep2_dbl_projc(r, p);
}
__device__
#if INLINE == 0
__noinline__
#endif
static void ep2_add_projc_mix(ep2_t r, ep2_t p, ep2_t q) {
	fp2_t t0, t1, t2, t3, t4, t5, t6;

 t0[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t0[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t2[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t2[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t3[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t3[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t4[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t4[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t5[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t5[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 t6[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t6[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
		if (p->coord != BASIC) {
			/* t0 = z1^2. */
			fp2_sqr(t0, p->z);

			/* t3 = U2 = x2 * z1^2. */
			fp2_mul(t3, q->x, t0);

			/* t1 = S2 = y2 * z1^3. */
			fp2_mul(t1, t0, p->z);
			fp2_mul(t1, t1, q->y);

			/* t3 = H = U2 - x1. */
			fp2_sub(t3, t3, p->x);

			/* t1 = R = 2 * (S2 - y1). */
			fp2_sub(t1, t1, p->y);
		} else {
			/* H = x2 - x1. */
			fp2_sub(t3, q->x, p->x);

			/* t1 = R = 2 * (y2 - y1). */
			fp2_sub(t1, q->y, p->y);
		}

		/* t2 = HH = H^2. */
		fp2_sqr(t2, t3);

		/* If E is zero. */
		if (fp2_is_zero(t3)) {
			if (fp2_is_zero(t1)) {
				/* If I is zero, p = q, should have doubled. */
				ep2_dbl_projc(r, p);
			} else {
				/* If I is not zero, q = -p, r = infinity. */
				ep2_set_infty(r);
			}
		} else {
			/* t5 = J = H * HH. */
			fp2_mul(t5, t3, t2);

			/* t4 = V = x1 * HH. */
			fp2_mul(t4, p->x, t2);

			/* x3 = R^2 - J - 2 * V. */
			fp2_sqr(r->x, t1);
			fp2_sub(r->x, r->x, t5);
			fp2_dbl(t6, t4);
			fp2_sub(r->x, r->x, t6);

			/* y3 = R * (V - x3) - Y1 * J. */
			fp2_sub(t4, t4, r->x);
			fp2_mul(t4, t4, t1);
			fp2_mul(t1, p->y, t5);
			fp2_sub(r->y, t4, t1);

			if (p->coord != BASIC) {
				/* z3 = z1 * H. */
				fp2_mul(r->z, p->z, t3);
			} else {
				/* z3 = H. */
				fp2_copy(r->z, t3);
			}
		}
		r->coord = PROJC;
}
__device__
#if INLINE == 0
__noinline__
#endif
static void ep2_add_projc_imp(ep2_t r, ep2_t p, ep2_t q) {
#if defined(EP_MIXED) && defined(STRIP)
        ep2_add_projc_mix(r, p, q);
#else /* General addition. */
        fp2_t t0, t1, t2, t3, t4, t5, t6;

 t0[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t0[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t2[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t2[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t3[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t3[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t4[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t4[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t5[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t5[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t6[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t6[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

                if (q->coord == BASIC) {
                        ep2_add_projc_mix(r, p, q);
                } else {
                        /* t0 = z1^2. */
                        fp2_sqr(t0, p->z);

                        /* t1 = z2^2. */
                        fp2_sqr(t1, q->z);

                        /* t2 = U1 = x1 * z2^2. */
                        fp2_mul(t2, p->x, t1);

                        /* t3 = U2 = x2 * z1^2. */
                        fp2_mul(t3, q->x, t0);

                        /* t6 = z1^2 + z2^2. */
                        fp2_add(t6, t0, t1);

                        /* t0 = S2 = y2 * z1^3. */
                        fp2_mul(t0, t0, p->z);
                        fp2_mul(t0, t0, q->y);

                        /* t1 = S1 = y1 * z2^3. */
                        fp2_mul(t1, t1, q->z);
                        fp2_mul(t1, t1, p->y);

                        /* t3 = H = U2 - U1. */
                        fp2_sub(t3, t3, t2);
                        /* t0 = R = 2 * (S2 - S1). */
                        fp2_sub(t0, t0, t1);

                        fp2_dbl(t0, t0);

                        /* If E is zero. */
                        if (fp2_is_zero(t3)) {
                                if (fp2_is_zero(t0)) {
                                        /* If I is zero, p = q, should have doubled. */
                                        ep2_dbl_projc(r, p);
                                } else {
                                        /* If I is not zero, q = -p, r = infinity. */
                                        ep2_set_infty(r);
                                }
                        } else {
                                /* t4 = I = (2*H)^2. */
                                fp2_dbl(t4, t3);
                                fp2_sqr(t4, t4);

                                /* t5 = J = H * I. */
                                fp2_mul(t5, t3, t4);

                                /* t4 = V = U1 * I. */
                                fp2_mul(t4, t2, t4);

                                /* x3 = R^2 - J - 2 * V. */
                                fp2_sqr(r->x, t0);
                                fp2_sub(r->x, r->x, t5);
                                fp2_dbl(t2, t4);
                                fp2_sub(r->x, r->x, t2);

                                /* y3 = R * (V - x3) - 2 * S1 * J. */
                                fp2_sub(t4, t4, r->x);
                                fp2_mul(t4, t4, t0);
                                fp2_mul(t1, t1, t5);
                                fp2_dbl(t1, t1);
                                fp2_sub(r->y, t4, t1);

                                /* z3 = ((z1 + z2)^2 - z1^2 - z2^2) * H. */
                                fp2_add(r->z, p->z, q->z);
                                fp2_sqr(r->z, r->z);
                                fp2_sub(r->z, r->z, t6);
                                fp2_mul(r->z, r->z, t3);
                        }
                }
                r->coord = PROJC;
#endif
}

__device__
#if INLINE == 0
__noinline__
#endif
void ep2_add_projc(ep2_t r, ep2_t p, ep2_t q) {
        if (ep2_is_infty(p)) {
                ep2_copy(r, q);
                return;
        }

        if (ep2_is_infty(q)) {
                ep2_copy(r, p);
                return;
        }

        if (p == q) {
                /* TODO: This is a quick hack. Should we fix this? */
                ep2_dbl(r, p);
                return;
        }

        ep2_add_projc_imp(r, p, q);
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep2_add(ep2_t r, ep2_t p, ep2_t q) {
        ep2_add_projc(r, p, q);
}

__device__
#if INLINE == 0
__noinline__
#endif
void ep2_neg(ep2_t r, ep2_t p) {
	if (ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	if (r != p) {
		fp2_copy(r->x, p->x);
		fp2_copy(r->z, p->z);
	}

	fp2_neg(r->y, p->y);

	r->coord = p->coord;
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep2_mul_basic(ep2_t r, ep2_t p, const bn_t k) {
	int i, l;
	ep2_t t;

  t = (ep2_t)malloc(sizeof(ep2_st));
  t->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

		l = bn_bits(k);

		if (bn_get_bit(k, l - 1)) {
			ep2_copy(t, p);
		} else {
			ep2_set_infty(t);
		}

		for (i = l - 2; i >= 0; i--) {
			ep2_dbl(t, t);
			if (bn_get_bit(k, i)) {
				ep2_add(t, t, p);
			}
		}

		ep2_copy(r, t);
		ep2_norm(r, r);
		if (bn_sign(k) == RLC_NEG) {
			ep2_neg(r, r);
		}
}

__device__
#if INLINE == 0
__noinline__
#endif
void ep2_sub(ep2_t r, ep2_t p, ep2_t q) {
	ep2_t t;

  t = (ep2_t)malloc(sizeof(ep2_st));
  t->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

	if (p == q) {
		ep2_set_infty(r);
		return;
	}


		ep2_neg(t, q);
		ep2_add(r, p, t);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_frb(fp2_t c, fp2_t a, int i) {
        switch (i % 2) {
                case 0:
                        fp2_copy(c, a);
                        break;
                case 1:
                        /* (a_0 + a_1 * u)^p = a_0 - a_1 * u. */
                        fp_copy(c[0], a[0]);
                        fp_neg(c[1], a[1]);
                        break;
        }
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_exp(fp2_t c, fp2_t a, bn_t b) {
        fp2_t t;

        if (bn_is_zero(b)) {
                fp2_set_dig(c, 1);
                return;
        }

 t[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));


                fp2_copy(t, a);
                for (int i = bn_bits(b) - 2; i >= 0; i--) {
                        fp2_sqr(t, t);
                        if (bn_get_bit(b, i)) {
                                fp2_mul(t, t, a);
                        }
                }

                if (bn_sign(b) == RLC_NEG) {
                        fp2_inv(c, t);
                } else {
                        fp2_copy(c, t);
                }
}

__device__
#if INLINE == 0
__noinline__
#endif
void bn_div1_low(dig_t *c, dig_t *d, const dig_t *a, int size, dig_t b) {
        dig_t q, r, w = 0;

        for (int i = size - 1; i >= 0; i--) {
                RLC_DIV_DIG(q, r, w, a[i], b);
                c[i] = q;
                w = r;
        }
        *d = (dig_t)w;
}

__device__
#if INLINE == 0
__noinline__
#endif
void bn_div_dig(bn_t c, const bn_t a, dig_t b) {
        bn_t q;
        dig_t r;

 q = (bn_t) malloc(sizeof(bn_st));
 q->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 q->alloc = RLC_BN_SIZE;
 q->sign = RLC_POS;
 q->used = RLC_FP_DIGS;

        if (b == 0) {
                printf("bn_div_dig error..\n");
                return;
        }

        if (b == 1 || bn_is_zero(a) == 1) {
                if (c != NULL) {
                        bn_copy(c, a);
                }
                return;
        }

                bn_new_size(q, a->used);
                bn_div1_low(q->dp, &r, (const dig_t *)a->dp, a->used, b);

                if (c != NULL) {
                        q->used = a->used;
                        q->sign = a->sign;
                        bn_trim(q);
                        bn_copy(c, q);
                }
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_mul_nor_basic(fp2_t c, fp2_t a) {
	fp2_t t;
	bn_t b;

 t[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 b = (bn_t) malloc(sizeof(bn_st));
 b->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 b->alloc = RLC_BN_SIZE;
 b->sign = RLC_POS;
 b->used = RLC_FP_DIGS;

		/* If p = 3 mod 8, (1 + i) is a QNR/CNR. */
		fp_neg(t[0], a[1]);
		fp_add(c[1], a[0], a[1]);
		fp_add(c[0], t[0], a[0]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep2_frb(ep2_t r, ep2_t p, int i) {
 fp2_t ep2_frb0;
 fp2_t ep2_frb1;
 fp2_t t1,t0;
 bn_t e;

 ep2_frb0[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 ep2_frb0[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 ep2_frb1[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 ep2_frb1[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 t1[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t1[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 t0[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 t0[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));


 fp2_set_dig(t1, 1);
 fp2_mul_nor_basic(t0, t1);

 e = (bn_t) malloc(sizeof(bn_st));
 e->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
 e->alloc = RLC_BN_SIZE;
 e->sign = RLC_POS;
 e->used = RLC_FP_DIGS;

 dv_copy(e->dp, shared_prime, RLC_FP_DIGS);
 bn_sub_dig(e, e, 1);
 bn_div_dig(e, e, 6);
 fp2_exp(t0, t0, e);


 fp2_sqr(t1, t0);

 fp_copy(ep2_frb0[0], t1[0]);
 fp_copy(ep2_frb0[1], t1[1]);
 fp2_inv(ep2_frb0,ep2_frb0);

 fp2_mul(t1, t1, t0);
 fp_copy(ep2_frb1[0], t1[0]);
 fp_copy(ep2_frb1[1], t1[1]);
 fp2_inv(ep2_frb1,ep2_frb1);


// ep2_frb: 
// 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000
// 1A0111EA397FE699 EC02408663D4DE85 AA0D857D89759AD4 897D29650FB85F9B 409427EB4F49FFFD 8BFD00000000AAAD
// 135203E60180A68E E2E9C448D77A2CD9 1C3DEDD930B1CF60 EF396489F61EB45E 304466CF3E67FA0A F1EE7B04121BDEA2
// 06AF0E0437FF400B 6831E36D6BD17FFE 48395DABC2D3435E 77F76E17009241C5 EE67992F72EC05F4 C81084FBEDE3CC09


	ep2_copy(r, p);
	for (; i > 0; i--) {
		fp2_frb(r->x, r->x, 1);
		fp2_frb(r->y, r->y, 1);
		fp2_frb(r->z, r->z, 1);
		fp2_mul(r->x, r->x, ep2_frb0);
		fp2_mul(r->y, r->y, ep2_frb1);
	}
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_set_2b(bn_t a, int b) { 
        int i, d;

        if (b < 0) {
                bn_zero(a);
        } else {
                RLC_RIP(b, d, b);

                bn_grow(a, d + 1);
                for (i = 0; i < d; i++) {
                        a->dp[i] = 0;
                }
                a->used = d + 1;
                a->dp[d] = ((dig_t)1 << b);
                a->sign = RLC_POS;
        }
}

__device__
#if INLINE == 0
__noinline__
#endif
void bn_set_bit(bn_t a, int bit, int value) {
        int d;

        if (bit < 0) {
                printf("error in bn_set_bit\n");
                return;
        }

        RLC_RIP(bit, d, bit);

        bn_grow(a, d);

        if (value == 1) {
                a->dp[d] |= ((dig_t)1 << bit);
                if ((d + 1) > a->used) {
                        a->used = d + 1;
                }
        } else {
                a->dp[d] &= ~((dig_t)1 << bit);
                bn_trim(a);
        }
}

__device__
#if INLINE == 0
__noinline__
#endif
static void ep2_mul_cof_b12(ep2_t r, ep2_t p) {
	bn_t x;
	ep2_t t0, t1, t2, t3;


  t0 = (ep2_t)malloc(sizeof(ep2_st));
  t0->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t0->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t0->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t0->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t0->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t0->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t1 = (ep2_t)malloc(sizeof(ep2_st));
  t1->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t1->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t1->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t1->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t1->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t1->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t2 = (ep2_t)malloc(sizeof(ep2_st));
  t2->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t2->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t2->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t2->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t2->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t2->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t3 = (ep2_t)malloc(sizeof(ep2_st));
  t3->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t3->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t3->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t3->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t3->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t3->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  x = (bn_t ) malloc(sizeof(bn_st));
  x->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
  x->alloc = RLC_BN_SIZE;
  x->sign = RLC_POS;

                /* x = -(2^63 + 2^62 + 2^60 + 2^57 + 2^48 + 2^16). */
                bn_set_2b(x, 63);
                bn_set_bit(x, 62, 1);
                bn_set_bit(x, 60, 1);
                bn_set_bit(x, 57, 1);
                bn_set_bit(x, 48, 1);
                bn_set_bit(x, 16, 1);
                bn_neg(x, x);


//		fp_prime_get_par(x);

		/* Compute t0 = xP. */
		ep2_mul_basic(t0, p, x);
		/* Compute t1 = [x^2]P. */
		ep2_mul_basic(t1, t0, x);

		/* t2 = (x^2 - x - 1)P = x^2P - x*P - P. */
		ep2_sub(t2, t1, t0);
		ep2_sub(t2, t2, p);
		/* t3 = \psi(x - 1)P. */
		ep2_sub(t3, t0, p);
		ep2_frb(t3, t3, 1);
		ep2_add(t2, t2, t3);
		/* t3 = \psi^2(2P). */
		ep2_dbl(t3, p);
		ep2_frb(t3, t3, 2);
		ep2_add(t2, t2, t3);
		ep2_norm(r, t2);
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep_set_infty(ep_t p) {
        fp_zero(p->x);
        fp_zero(p->y);
        fp_zero(p->z);
        p->coord = BASIC;
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep_copy(ep_t r, const ep_t p) {
        fp_copy(r->x, p->x);
        fp_copy(r->y, p->y);
        fp_copy(r->z, p->z);
        r->coord = p->coord;
}    
__device__
#if INLINE == 0
__noinline__
#endif
int ep_is_infty(const ep_t p) {
        return (fp_is_zero(p->z) == 1);
} 
__device__
#if INLINE == 0
__noinline__
#endif
void ep_curve_mul_b3(fp_t c, const fp_t a) {
 fp_t tw; 
 tw = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 fp_set_dig(tw, 12);
// printf(" now in ep_curve_mul_b3: \n");
// printf("a: ");
// fp_print(a);
// printf("tw: ");
// fp_print(tw);
 fp_mul(c, a, tw);
// fp_print(c);
 free(tw);
}

__device__
#if INLINE == 0
__noinline__
#endif
static void ep_add_projc_mix(ep_t r, const ep_t p, const ep_t q) {
	fp_t t0, t1, t2, t3, t4, t5;
	fp_t b3;

        t0 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        t1 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        t2 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        t3 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        t4 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        t5 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

        b3 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        b3[0] = 0;
        b3[1] = 0;
        b3[2] = 0;
        b3[3] = 0;
        b3[4] = 0;
        b3[5] = 0;

//	RLC_TRY {

		/* Formulas for mixed addition from
		 * "Complete addition formulas for prime order elliptic curves"
		 * by Joost Renes, Craig Costello, and Lejla Batina
		 * https://eprint.iacr.org/2015/1060.pdf
		 */

		 fp_mul(t0, p->x, q->x);
		 fp_mul(t1, p->y, q->y);
		 fp_add(t3, q->x, q->y);
		 fp_add(t4, p->x, p->y);
		 fp_mul(t3, t3, t4);
		 fp_add(t4, t0, t1);
		 fp_sub(t3, t3, t4);

//		 if (ep_curve_opt_a() == RLC_ZERO) {
 			/* Cost of 11M + 2m_3b + 13a. */
			if (p->coord == BASIC) {
				/* Save 1M + 1m_3b if z1 = 1. */
				fp_add(t4, q->y, p->y);
	 			fp_add(r->y, q->x, p->x);
                                b3[0] = 12;
				fp_add(r->z, t1, b3);
	 			fp_sub(t1, t1, b3);
			} else {
				fp_mul(t4, q->y, p->z);
				fp_add(t4, t4, p->y);
	 			fp_mul(r->y, q->x, p->z);
	 			fp_add(r->y, r->y, p->x);
	 			ep_curve_mul_b3(t2, p->z);
				fp_add(r->z, t1, t2);
	 			fp_sub(t1, t1, t2);
			}
			fp_dbl(r->x, t0);
			fp_add(t0, t0, r->x);
 			ep_curve_mul_b3(r->y, r->y);
 			fp_mul(r->x, t4, r->y);
 			fp_mul(t2, t3, t1);
 			fp_sub(r->x, t2, r->x);
 			fp_mul(r->y, t0, r->y);
 			fp_mul(t1, t1, r->z);
 			fp_add(r->y, t1, r->y);
 			fp_mul(t0, t0, t3);
 			fp_mul(r->z, r->z, t4);
 			fp_add(r->z, r->z, t0);
// 		 } else if (ep_curve_opt_a() == RLC_MIN3) {
// 			/* Cost of 11M + 2m_b + 23a. */
//			if (p->coord == BASIC) {
//				/* Save 2M + 3a if z1 = 1. */
//				fp_set_dig(t2, 3);
//	 			fp_add(t4, q->y, p->y);
//	 			fp_add(r->y, q->x, p->x);
//	 			fp_sub(r->x, r->y, ep_curve_get_b());
//			} else {
//				fp_dbl(t2, p->z);
//	 			fp_add(t2, t2, p->z);
//				fp_mul(t4, q->y, p->z);
//	 			fp_add(t4, t4, p->y);
//	 			fp_mul(r->y, q->x, p->z);
//	 			fp_add(r->y, r->y, p->x);
//				ep_curve_mul_b(r->z, p->z);
//	 			fp_sub(r->x, r->y, r->z);
//			}
// 			fp_dbl(r->z, r->x);
// 			fp_add(r->x, r->x, r->z);
// 			fp_sub(r->z, t1, r->x);
// 			fp_add(r->x, t1, r->x);
// 			ep_curve_mul_b(r->y, r->y);
// 			fp_sub(r->y, r->y, t2);
// 			fp_sub(r->y, r->y, t0);
// 			fp_dbl(t1, r->y);
// 			fp_add(r->y, t1, r->y);
// 			fp_dbl(t1, t0);
// 			fp_add(t0, t1, t0);
// 			fp_sub(t0, t0, t2);
// 			fp_mul(t1, t4, r->y);
// 			fp_mul(t2, t0, r->y);
// 			fp_mul(r->y, r->x, r->z);
// 			fp_add(r->y, r->y, t2);
// 			fp_mul(r->x, t3, r->x);
// 			fp_sub(r->x, r->x, t1);
// 			fp_mul(r->z, t4, r->z);
// 			fp_mul(t1, t3, t0);
// 			fp_add(r->z, r->z, t1);
// 		} else {
//			/* Cost of 11M + 3m_a + 2m_3b + 17a. */
//			if (p->coord == BASIC) {
//				/* Save 1M + 1m_a + 1m_3b if z1 = 1. */
//				fp_copy(t2, ep_curve_get_a());
//				fp_add(t4, q->x, p->x);
//				fp_add(t5, q->y, p->y);
//				ep_curve_mul_a(r->z, t4);
//				fp_add(r->z, r->z, ep_curve_get_b3());
//			} else {
//				ep_curve_mul_a(t2, p->z);
//				fp_mul(t4, q->x, p->z);
//				fp_add(t4, t4, p->x);
//				fp_mul(t5, q->y, p->z);
//				fp_add(t5, t5, p->y);
//				ep_curve_mul_b3(r->x, p->z);
//				ep_curve_mul_a(r->z, t4);
//				fp_add(r->z, r->x, r->z);
//			}
//			fp_sub(r->x, t1, r->z);
//			fp_add(r->z, t1, r->z);
//			fp_mul(r->y, r->x, r->z);
//			fp_dbl(t1, t0);
//			fp_add(t1, t1, t0);
//			ep_curve_mul_b3(t4, t4);
//			fp_add(t1, t1, t2);
//			fp_sub(t2, t0, t2);
//			ep_curve_mul_a(t2, t2);
//			fp_add(t4, t4, t2);
//			fp_mul(t0, t1, t4);
//			fp_add(r->y, r->y, t0);
//			fp_mul(t0, t5, t4);
//			fp_mul(r->x, t3, r->x);
//			fp_sub(r->x, r->x, t0);
//			fp_mul(t0, t3, t1);
//			fp_mul(r->z, t5, r->z);
//			fp_add(r->z, r->z, t0);
//		}

		r->coord = PROJC;
//	}
//	RLC_CATCH_ANY {
//		RLC_THROW(ERR_CAUGHT);
//	}
//	RLC_FINALLY {
//		fp_free(t0);
//		fp_free(t1);
//		fp_free(t2);
//		fp_free(t3);
//		fp_free(t4);
//		fp_free(t5);
//	}
 free(t0);
 free(t1);
 free(t2);
 free(t3);
 free(t4);
 free(t5);
 free(b3);
}
__device__
#if INLINE == 0
__noinline__
#endif
static void ep_add_projc_imp(ep_t r, const ep_t p, const ep_t q) {
// #if defined(EP_MIXED) && defined(STRIP)
// 	/* If code size is a problem, leave only the mixed version. */
// 	ep_add_projc_mix(r, p, q);
// #else /* General addition. */
// 
// #if defined(EP_MIXED) || !defined(STRIP)
// 	/* Test if z2 = 1 only if mixed coordinates are turned on. */
// 	if (q->coord == BASIC) {
//  printf(" if defined(EP_MIXED) || !defined(STRIP) \n");
  ep_add_projc_mix(r, p, q);
// 		return;
// 	}
// #endif
//  printf(" ELSE \n");
// 
// 	fp_t t0, t1, t2, t3, t4, t5;
// 
// 	fp_null(t0);
// 	fp_null(t1);
// 	fp_null(t2);
// 	fp_null(t3);
// 	fp_null(t4);
// 	fp_null(t5);
// 
// 	RLC_TRY {
// 		fp_new(t0);
// 		fp_new(t1);
// 		fp_new(t1);
// 		fp_new(t3);
// 		fp_new(t4);
// 		fp_new(t5);
// 
// 		/* Formulas for point addition from
// 		 * "Complete addition formulas for prime order elliptic curves"
// 		 * by Joost Renes, Craig Costello, and Lejla Batina
// 		 * https://eprint.iacr.org/2015/1060.pdf
// 		 */
// 		fp_mul(t0, p->x, q->x);
// 		fp_mul(t1, p->y, q->y);
// 		fp_mul(t2, p->z, q->z);
// 		fp_add(t3, p->x, p->y);
// 		fp_add(t4, q->x, q->y);
// 		fp_mul(t3, t3, t4);
// 		fp_add(t4, t0, t1);
// 		fp_sub(t3, t3, t4);
// 		if (ep_curve_opt_a() == RLC_ZERO) {
// 			/* Cost of 12M + 2m_3b + 19a. */
//                         printf("ep_curve_opt_a() == RLC_ZERO \n");
// 			fp_add(t4, p->y, p->z);
// 			fp_add(t5, q->y, q->z);
// 			fp_mul(t4, t4, t5);
// 			fp_add(t5, t1, t2);
// 			fp_sub(t4, t4, t5);
// 			fp_add(r->y, q->x, q->z);
// 			fp_add(r->x, p->x, p->z);
// 			fp_mul(r->x, r->x, r->y);
// 			fp_add(r->y, t0, t2);
// 			fp_sub(r->y, r->x, r->y);
// 			fp_dbl(r->x, t0);
// 			fp_add(t0, t0, r->x);
// 			ep_curve_mul_b3(t2, t2);
// 			fp_add(r->z, t1, t2);
// 			fp_sub(t1, t1, t2);
// 			ep_curve_mul_b3(r->y, r->y);
// 			fp_mul(r->x, t4, r->y);
// 			fp_mul(t2, t3, t1);
// 			fp_sub(r->x, t2, r->x);
// 			fp_mul(r->y, t0, r->y);
// 			fp_mul(t1, t1, r->z);
// 			fp_add(r->y, t1, r->y);
// 			fp_mul(t0, t0, t3);
// 			fp_mul(r->z, r->z, t4);
// 			fp_add(r->z, r->z, t0);
// 		} else if (ep_curve_opt_a() == RLC_MIN3) {
// 			/* Cost of 12M + 2m_b + 29a. */
//                         printf("ep_curve_opt_a() == RLC_MIN3\n");
// 			fp_add(t4, p->y, p->z);
// 			fp_add(t5, q->y, q->z);
// 			fp_mul(t4, t4, t5);
// 			fp_add(t5, t1, t2);
// 			fp_sub(t4, t4, t5);
// 			fp_add(r->x, p->x, p->z);
// 			fp_add(r->y, q->x, q->z);
// 			fp_mul(r->x, r->x, r->y);
// 			fp_add(r->y, t0, t2);
// 			fp_sub(r->y, r->x, r->y);
// 			ep_curve_mul_b(r->z, t2);
// 			fp_sub(r->x, r->y, r->z);
// 			fp_dbl(r->z, r->x);
// 			fp_add(r->x, r->x, r->z);
// 			fp_sub(r->z, t1, r->x);
// 			fp_add(r->x, t1, r->x);
// 			ep_curve_mul_b(r->y, r->y);
// 			fp_dbl(t1, t2);
// 			fp_add(t2, t1, t2);
// 			fp_sub(r->y, r->y, t2);
// 			fp_sub(r->y, r->y, t0);
// 			fp_dbl(t1, r->y);
// 			fp_add(r->y, t1, r->y);
// 			fp_dbl(t1, t0);
// 			fp_add(t0, t1, t0);
// 			fp_sub(t0, t0, t2);
// 			fp_mul(t1, t4, r->y);
// 			fp_mul(t2, t0, r->y);
// 			fp_mul(r->y, r->x, r->z);
// 			fp_add(r->y, r->y, t2);
// 			fp_mul(r->x, t3, r->x);
// 			fp_sub(r->x, r->x, t1);
// 			fp_mul(r->z, t4, r->z);
// 			fp_mul(t1, t3, t0);
// 			fp_add(r->z, r->z, t1);
// 		} else {
// 			 /* Cost of 12M + 3m_a + 2_m3b + 23a. */
//                         printf("elseelseelse\n");
// 			fp_add(t4, p->x, p->z);
// 			fp_add(t5, q->x, q->z);
// 			fp_mul(t4, t4, t5);
// 			fp_add(t5, t0, t2);
// 			fp_sub(t4, t4, t5);
// 			fp_add(t5, p->y, p->z);
// 			fp_add(r->x, q->y, q->z);
// 			fp_mul(t5, t5, r->x);
// 			fp_add(r->x, t1, t2);
// 			fp_sub(t5, t5, r->x);
// 			ep_curve_mul_a(r->z, t4);
// 			ep_curve_mul_b3(r->x, t2);
// 			fp_add(r->z, r->x, r->z);
// 			fp_sub(r->x, t1, r->z);
// 			fp_add(r->z, t1, r->z);
// 			fp_mul(r->y, r->x, r->z);
// 			fp_dbl(t1, t0);
// 			fp_add(t1, t1, t0);
// 			ep_curve_mul_a(t2, t2);
// 			ep_curve_mul_b3(t4, t4);
// 			fp_add(t1, t1, t2);
// 			fp_sub(t2, t0, t2);
// 			ep_curve_mul_a(t2, t2);
// 			fp_add(t4, t4, t2);
// 			fp_mul(t0, t1, t4);
// 			fp_add(r->y, r->y, t0);
// 			fp_mul(t0, t5, t4);
// 			fp_mul(r->x, t3, r->x);
// 			fp_sub(r->x, r->x, t0);
// 			fp_mul(t0, t3, t1);
// 			fp_mul(r->z, t5, r->z);
// 			fp_add(r->z, r->z, t0);
// 		}
// 
// 		r->coord = PROJC;
// 	}
// 	RLC_CATCH_ANY {
// 		RLC_THROW(ERR_CAUGHT);
// 	}
// 	RLC_FINALLY {
// 		fp_free(t0);
// 		fp_free(t1);
// 		fp_free(t2);
// 		fp_free(t3);
// 		fp_free(t4);
// 		fp_free(t5);
// 	}
// #endif
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep_add_projc(ep_t r, const ep_t p, const ep_t q) {
        if (ep_is_infty(p)) {
                ep_copy(r, q);
                return;
        }

        if (ep_is_infty(q)) {
                ep_copy(r, p);
                return;
        }

        ep_add_projc_imp(r, p, q);
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep_add(ep_t r, const ep_t p, const ep_t q) {
 ep_add_projc(r,p,q);
}

__device__
#if INLINE == 0
__noinline__
#endif
static void ep_norm_imp(ep_t r, const ep_t p, int inv) {
 fp_t t;
 
 if (p->coord != BASIC) {
  t = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  if (inv) {
   fp_copy(r->z, p->z);
  } else {
   fp_inv(r->z, p->z);
  }
  switch (p->coord) {
   case PROJC:
    fp_mul(r->x, p->x, r->z);
    fp_mul(r->y, p->y, r->z);
    break;
   case JACOB:
    fp_sqr(t, r->z);
    fp_mul(r->x, p->x, t);
    fp_mul(t, t, r->z);
    fp_mul(r->y, p->y, t);
    free(t);
    break;
   default:
    ep_copy(r, p);
    break;
   }
  fp_set_dig(r->z, 1);
 }
 r->coord = BASIC;
}
__device__
#if INLINE == 0
__noinline__
#endif
static void ep_norm(ep_t r, const ep_t p) {
        if (ep_is_infty(p)) {
                ep_set_infty(r);
                return;
        } 
                
        if (p->coord == BASIC) {
                /* If the point is represented in affine coordinates, just copy it. */
                ep_copy(r, p);
                return;
        }
#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)
        ep_norm_imp(r, p, 0);
#endif /* EP_ADD == PROJC */

}

__device__
#if INLINE == 0
__noinline__
#endif
void ep_neg(ep_t r, const ep_t p) {
        if (ep_is_infty(p)) {
                ep_set_infty(r);
                return;
        }

        if (r != p) {
                fp_copy(r->x, p->x); 
                fp_copy(r->z, p->z);
        }

        fp_neg(r->y, p->y);

        r->coord = p->coord;
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp_inv_sim(fp_t *c, const fp_t *a, int n) {
        int i;
        fp_t u, *t = (fp_t*) malloc((n) * sizeof(fp_t));
  
                
//        RLC_TRY {
                if (t == NULL) {
                        printf("No memory left in fp_inv_sim...\n");
                }       
                for (i = 0; i < n; i++) {
                        t[i] = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
                }
                        u = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
                        
                fp_copy(c[0], a[0]);
                fp_copy(t[0], a[0]);
      
                for (i = 1; i < n; i++) {
                        fp_copy(t[i], a[i]);
                        fp_mul(c[i], c[i - 1], a[i]);
                }
                        
                fp_inv(u, c[n - 1]);
        
                for (i = n - 1; i > 0; i--) {
                        fp_mul(c[i], u, c[i - 1]);
                        fp_mul(u, u, t[i]);
                }
                fp_copy(c[0], u);
//        }
//        RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        }
//        RLC_FINALLY {
               for (i = 0; i < n; i++) {
                        free(t[i]);
                }
//                fp_free(u);
//                RLC_FREE(t);
//        }
}

__device__
#if INLINE == 0
__noinline__
#endif
void ep_norm_sim(ep_t *r, const ep_t *t, int n) {
        int i;
        fp_t* a = (fp_t*) malloc((n) * sizeof(fp_t));

                if (a == NULL) {
                        printf("No memory left in ep_norm_sim...\n");
                }
                for (i = 0; i < n; i++) {
//                        fp_null(a[i]);
//                        fp_new(a[i]);
// itt át kell gondolni hogy mennyit foglalunk
                        a[i] = (fp_t)malloc(RLC_BN_SIZE * sizeof(dig_t));
                        fp_copy(a[i], t[i]->z);
                }

                fp_inv_sim(a, (const fp_t *)a, n);
                for (i = 0; i < n; i++) {
                        fp_copy(r[i]->x, t[i]->x);
                        fp_copy(r[i]->y, t[i]->y);
                        if (!ep_is_infty(t[i])) {
                                fp_copy(r[i]->z, a[i]);
                        }
                }

                for (i = 0; i < n; i++) {
                        ep_norm_imp(r[i], r[i], 1);
                }
          for (i = 0; i < n; i++) {
              free(a[i]);
             }
}

__device__
#if INLINE == 0
__noinline__
#endif
static void ep_dbl_projc_imp(ep_t r, const ep_t p) {
	fp_t t0, t1, t2, t3, t4, t5;
	fp_t b3;


        t0 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        t1 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        t2 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        t3 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        t4 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        t5 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

        b3 = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
        b3[0] = 0;
        b3[1] = 0;
        b3[2] = 0;
        b3[3] = 0;
        b3[4] = 0;
        b3[5] = 0;
		/* Formulas for point doubling from
		 * "Complete addition formulas for prime order elliptic curves"
		 * by Joost Renes, Craig Costello, and Lejla Batina
		 * https://eprint.iacr.org/2015/1060.pdf
		 */
//		 if (ep_curve_opt_a() == RLC_ZERO) {
			/* Cost of 6M + 2S + 1m_3b + 9a. */
			fp_sqr(t0, p->y);
// printf(" t0: \n");
//                        fp_print(t0);

			fp_mul(t3, p->x, p->y);
// printf(" t3: \n");
//                        fp_print(t3);


 			if (p->coord == BASIC) {
				/* Save 1M + 1S + 1m_b3 if z1 = 1. */
				fp_copy(t1, p->y);
// printf(" t1: \n");
//                        fp_print(t1);

                                b3[0] = 12;
				fp_copy(t2, b3);
// printf(" t2: \n");
//                        fp_print(t2);

 			} else {
				fp_mul(t1, p->y, p->z);
// printf(" t1: \n");
//                        fp_print(t1);

				fp_sqr(t2, p->z);
// printf(" t2: \n");
//                        fp_print(t2);

				ep_curve_mul_b3(t2, t2);
//                        fp_print(t2);

 			}
			fp_dbl(r->z, t0);
			fp_dbl(r->z, r->z);
			fp_dbl(r->z, r->z);
 			fp_mul(r->x, t2, r->z);
			fp_add(r->y, t0, t2);
			fp_mul(r->z, t1, r->z);
			fp_dbl(t1, t2);
			fp_add(t2, t1, t2);
			fp_sub(t0, t0, t2);
			fp_mul(r->y, t0, r->y);
			fp_add(r->y, r->x, r->y);
			fp_mul(r->x, t0, t3);
			fp_dbl(r->x, r->x);
//		} else {
//			fp_sqr(t0, p->x);
//			fp_sqr(t1, p->y);
//			fp_mul(t3, p->x, p->y);
//			fp_dbl(t3, t3);
//			fp_mul(t4, p->y, p->z);
//
//			if (ep_curve_opt_a() == RLC_MIN3) {
//				/* Cost of 8M + 3S + 2mb + 21a. */
//				if (p->coord == BASIC) {
//					/* Save 1S + 1m_b + 2a if z1 = 1. */
//					fp_set_dig(t2, 3);
//					fp_copy(r->y, ep_curve_get_b());
//				} else {
//					fp_sqr(t2, p->z);
//					ep_curve_mul_b(r->y, t2);
//					fp_dbl(t5, t2);
//					fp_add(t2, t2, t5);
//				}
//				fp_mul(r->z, p->x, p->z);
//				fp_dbl(r->z, r->z);
//				fp_sub(r->y, r->y, r->z);
//				fp_dbl(r->x, r->y);
//				fp_add(r->y, r->x, r->y);
//				fp_sub(r->x, t1, r->y);
//				fp_add(r->y, t1, r->y);
//				fp_mul(r->y, r->x, r->y);
//				fp_mul(r->x, t3, r->x);
//				ep_curve_mul_b(r->z, r->z);
//				fp_sub(t3, r->z, t2);
//				fp_sub(t3, t3, t0);
//				fp_dbl(r->z, t3);
//				fp_add(t3, t3, r->z);
//				fp_dbl(r->z, t0);
//				fp_add(t0, t0, r->z);
//				fp_sub(t0, t0, t2);
//			} else {
//				/* Common cost of 8M + 3S + 3m_a + 2m_3b + 15a. */
//				if (p->coord == BASIC) {
//					/* Save 1S + 1m_b + 1m_a if z1 = 1. */
//					fp_copy(r->y, ep_curve_get_b3());
//					fp_copy(t2, ep_curve_get_a());
//				} else {
//					fp_sqr(t2, p->z);
//					ep_curve_mul_b3(r->y, t2);
//					ep_curve_mul_a(t2, t2);
//				}
//				fp_mul(r->z, p->x, p->z);
//				fp_dbl(r->z, r->z);
//				ep_curve_mul_a(r->x, r->z);
//				fp_add(r->y, r->x, r->y);
//				fp_sub(r->x, t1, r->y);
//				fp_add(r->y, t1, r->y);
//				fp_mul(r->y, r->x, r->y);
//				fp_mul(r->x, t3, r->x);
//				ep_curve_mul_b3(r->z, r->z);
//				fp_sub(t3, t0, t2);
//				ep_curve_mul_a(t3, t3);
//				fp_add(t3, t3, r->z);
//				fp_dbl(r->z, t0);
//				fp_add(t0, t0, r->z);
//				fp_add(t0, t0, t2);
//			}
//			/* Common part with renamed variables. */
//			fp_mul(t0, t0, t3);
//			fp_add(r->y, r->y, t0);
//			fp_dbl(t2, t4);
//			fp_mul(t0, t2, t3);
//			fp_sub(r->x, r->x, t0);
//			fp_mul(r->z, t2, t1);
//			fp_dbl(r->z, r->z);
//			fp_dbl(r->z, r->z);
//		}

 r->coord = PROJC;
 free(t0);
 free(t1);
 free(t2);
 free(t3);
 free(t4);
 free(t5);
 free(b3);
// printf("LEAVING ep_dbl_projc_imp... \n");
}

__device__
#if INLINE == 0
__noinline__
#endif
void ep_dbl_projc(ep_t r, const ep_t p) {
        if (ep_is_infty(p)) {
                ep_set_infty(r);
                return;
        }

        ep_dbl_projc_imp(r, p);
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep_dbl(ep_t r, const ep_t p) {
 ep_dbl_projc(r,p);
}

__device__
#if INLINE == 0
__noinline__
#endif
void ep_mul_pre_basic(ep_t *t) {
        bn_t n;
        ep_t p;

//                ep_curve_get_ord(n);
        n = (bn_t) malloc(sizeof(bn_st));
        n->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
        n->alloc = RLC_BN_SIZE;
        n->used = 4;
        n->sign = RLC_POS;
// Ezeket be lehet drótozni hexában
        n->dp[0] = 18446744069414584321;
        n->dp[1] = 6034159408538082302;
        n->dp[2] = 3691218898639771653;
        n->dp[3] = 8353516859464449352;

        p = (ep_t) malloc(sizeof(ep_st));

// nem tudom hogy ez nem okoz-e gondot ha a stack-en allokálódik és nem malloc-olva van a memória

//        p->x = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
//        p->y = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
//        p->z = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

        p->coord = BASIC;
        p->x[0] = 18103045581585958587;
        p->x[1] = 7806400890582735599;
        p->x[2] = 11623291730934869080;
        p->x[3] = 14080658508445169925;
        p->x[4] = 2780237799254240271;
        p->x[5] = 1725392847304644500;

        p->y[0] = 912580534683953121;
        p->y[1] = 15005087156090211044;
        p->y[2] = 61670280795567085;
        p->y[3] = 18227722000993880822;
        p->y[4] = 11573741888802228964;
        p->y[5] = 627113611842199793;

        p->z[0] = 1;
        p->z[1] = 0;
        p->z[2] = 0;
        p->z[3] = 0;
        p->z[4] = 0;
        p->z[5] = 0;
        printf(" Precalculating table: \n");
        ep_copy(t[0], p);
// printf("bn_bits(n) %d \n",bn_bits(n));
                for (int i = 1; i < bn_bits(n); i++) {
// printf(" i: %d \n",i);
// ep_print(t[i-1]);
                        ep_dbl(t[i], t[i - 1]);
// ep_print(t[i]);

         ep_dbl(t[i], t[i - 1]);
        }
        printf("Generator doubling done \n");
        ep_norm_sim(t + 1, (const ep_t *)t + 1, bn_bits(n) - 1);
        printf("Generator normalization done \n");
}

__device__
#if INLINE == 0
__noinline__
#endif
void ep_mul_fix_basic(ep_t r, const ep_t *t, const bn_t k) {
        bn_t n, _k;

        if (bn_is_zero(k)) {
                ep_set_infty(r);
                return;
        }

        _k = (bn_t) malloc(sizeof(bn_st));
        _k->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
        _k->alloc = RLC_BN_SIZE;
        _k->sign = RLC_POS;

        n = (bn_t) malloc(sizeof(bn_st));
        n->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
        n->alloc = RLC_BN_SIZE;
        n->used = 4;
        n->sign = RLC_POS;
        n->dp[0] = 18446744069414584321;
        n->dp[1] = 6034159408538082302;
        n->dp[2] = 3691218898639771653;
        n->dp[3] = 8353516859464449352;

//                ep_curve_get_ord(n);
                bn_copy(_k, k);
                if (bn_cmp_abs(_k, n) == RLC_GT) {
                        bn_mod_basic(_k, _k, n);
                }

                ep_set_infty(r);
                for (int i = 0; i < bn_bits(_k); i++) {
                        if (bn_get_bit(_k, i)) {
// printf("i: %d \n t[i]",i);
// ep_print(t[i]);
                                ep_add(r, r, t[i]);
// ep_print(r);
                        }
                }
                ep_norm(r, r);
                if (bn_sign(_k) == RLC_NEG) {
                        ep_neg(r, r);
                }
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep_mul_fix(ep_t r, const ep_t *t, const bn_t k) {
 ep_mul_fix_basic(r,t,k);
}

__device__
#if INLINE == 0
__noinline__
#endif
void ep_mul_gen(ep_t r, const bn_t k) {
        ep_st *ep_ptr[382];
        for(int i = 0; i<382;i++){
         ep_ptr[i] = (ep_st*) malloc(sizeof(ep_st));
        }
        if (bn_is_zero(k)) {

                ep_set_infty(r);
                return;
        }

#ifdef EP_PRECO
        ep_mul_pre_basic(ep_ptr);
        clock_t start = clock();
        ep_mul_fix(r, ep_ptr, k);
        clock_t stop = clock();
        printf("ep_mul_fix took: %dM cycles \n",(int)(stop - start)/1000000);
#else
        ep_t g;

//        ep_null(g);
//        ep_new(g);
//        ep_curve_get_gen(g);
//        ep_mul(r, g, k);
#endif
 
 printf(" Public key: \n");
 ep_print(r);
        for(int i = 0; i<382;i++){
         free(ep_ptr[i]);
        }
}

__device__
#if INLINE == 0
__noinline__
#endif
void ep2_add_basic(ep2_t r, ep2_t p, ep2_t q) {
        if (ep2_is_infty(p)) {
                ep2_copy(r, q);
                return;
        }

        if (ep2_is_infty(q)) {
                ep2_copy(r, p);
                return;
        }

        ep2_add_basic_imp(r, NULL, p, q);
}
__device__
#if INLINE == 0
__noinline__
#endif
uint64_t xtou64(const char *str)
{
    uint64_t res = 0;
    char c;

    while ((c = *str++)) {
        char v = (c & 0xF) + (c >> 6) | ((c >> 3) & 0x8);
        res = (res << 4) | (uint64_t) v;
    }

    return res;
} 
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_set_dig(fp6_t a, dig_t b) { 
        fp2_set_dig(a[0], b);
        fp2_zero(a[1]);
        fp2_zero(a[2]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_zero(fp6_t a) {
        fp2_zero(a[0]);
        fp2_zero(a[1]);
        fp2_zero(a[2]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_set_dig(fp12_t a, dig_t b) {
        fp6_set_dig(a[0], b);
        fp6_zero(a[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void bn_get_dig(dig_t *c, const bn_t a) {
        *c = a->dp[0];
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t bn_rsh1_low(dig_t *c, const dig_t *a, int size) {
        int i;
        dig_t r, carry;

        c += size - 1;
        a += size - 1;
        carry = 0;
        for (i = size - 1; i >= 0; i--, a--, c--) {
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
void bn_hlv(bn_t c, const bn_t a) {
        bn_copy(c, a);
        bn_rsh1_low(c->dp, c->dp, c->used);
        bn_trim(c);
}

__device__
#if INLINE == 0
__noinline__
#endif
void bn_rec_naf(int8_t *naf, int *len, const bn_t k, int w) {
	int i, l;
	bn_t t;
	dig_t t0, mask;
	int8_t u_i;

	if (*len < (bn_bits(k) + 1)) {
		*len = 0;
                 printf(" no buffer in bn_rec_naf \n");
		return;
	}

  t = (bn_t ) malloc(sizeof(bn_st));
  t->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
  t->alloc = RLC_BN_SIZE;
  t->used = 1;
  t->sign = RLC_NEG;

		bn_abs(t, k);

		mask = RLC_MASK(w);
		l = (1 << w);

		memset(naf, 0, *len);

		i = 0;
		if (w == 2) {
			while (!bn_is_zero(t)) {
				if (!bn_is_even(t)) {
					bn_get_dig(&t0, t);
					u_i = 2 - (t0 & mask);
					if (u_i < 0) {
						bn_add_dig(t, t, -u_i);
					} else {
						bn_sub_dig(t, t, u_i);
					}
					*naf = u_i;
				} else {
					*naf = 0;
				}
				bn_hlv(t, t);
				i++;
				naf++;
			}
		} else {
			while (!bn_is_zero(t)) {
				if (!bn_is_even(t)) {
					bn_get_dig(&t0, t);
					u_i = t0 & mask;
					if (u_i > l / 2) {
						u_i = (int8_t)(u_i - l);
					}
					if (u_i < 0) {
						bn_add_dig(t, t, -u_i);
					} else {
						bn_sub_dig(t, t, u_i);
					}
					*naf = u_i;
				} else {
					*naf = 0;
				}
				bn_hlv(t, t);
				i++;
				naf++;
			}
		}
		*len = i;

}
__device__
#if INLINE == 0
__noinline__
#endif
void dv2_free(dv2_t c) {
                free(c[0]);
                free(c[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void dv4_free(dv4_t c) {
                dv2_free(c[0]);
                dv2_free(c[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void dv6_free(dv6_t c) {
                dv2_free(c[0]);
                dv2_free(c[1]);
                dv2_free(c[2]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void dv12_free(dv12_t c) {
                dv6_free(c[0]);
                dv6_free(c[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void dv2_null(dv2_t c) {
        for (int i = 0; i < RLC_FP_DIGS; i++) {
                c[0][i] = 0;
                c[1][i] = 0;
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_subc_low(dv2_t c, dv2_t a, dv2_t b) {
        fp_subc_low(c[0], a[0], b[0]);
        fp_subc_low(c[1], a[1], b[1]);
}     
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_rdcn_low(fp2_t c, dv2_t a) {
#if FP_RDC == MONTY
        fp_rdcn_low(c[0], a[0]);
        fp_rdcn_low(c[1], a[1]);
#else
        fp_rdc(c[0], a[0]);
        fp_rdc(c[1], a[1]);
#endif
}


__device__
#if INLINE == 0
__noinline__
#endif
void dv2_new(dv2_t t) {
        t[0] = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
        t[1] = (dv_t ) malloc( (RLC_DV_DIGS + RLC_PAD(RLC_DV_BYTES)/(RLC_DIG / 8))*sizeof(dig_t));
}
__device__
#if INLINE == 0
__noinline__
#endif
void dv6_new(dv6_t t) {
       dv2_new(t[0]);
       dv2_new(t[1]);
       dv2_new(t[2]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void dv12_new(dv12_t t) {
       dv6_new(t[0]);
       dv6_new(t[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void dv4_new(dv4_t t) {
       dv2_new(t[0]);
       dv2_new(t[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
dig_t fp_dbln_low(dig_t *c, const dig_t *a) {
        int i;
        dig_t carry, c0, c1, r0, r1;

        carry = 0;
        for (i = 0; i < RLC_FP_DIGS; i++, a++, c++) {
                r0 = (*a) + (*a);
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
dig_t fp_subd_low(dig_t *c, const dig_t *a, const dig_t *b) {
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
        return carry;
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_sqrn_low(dv2_t c, fp2_t a) {
	rlc_align dig_t t0[2 * RLC_FP_DIGS], t1[2 * RLC_FP_DIGS], t2[2 * RLC_FP_DIGS];

	/* t0 = (a0 + a1). */
#ifdef RLC_FP_ROOM
	/* if we have room for carries, we can avoid reductions here. */
	fp_addn_low(t0, a[0], a[1]);
#else
	fp_addm_low(t0, a[0], a[1]);
#endif
	/* t1 = (a0 - a1). */
	fp_subm_low(t1, a[0], a[1]);

#ifdef FP_QNRES

#ifdef RLC_FP_ROOM
	fp_dbln_low(t2, a[0]);
#else
	fp_dblm_low(t2, a[0]);
#endif
	/* c1 = 2 * a0 * a1. */
	fp_muln_low(c[1], t2, a[1]);
	/* c_0 = a_0^2 + a_1^2 * u^2. */
	fp_muln_low(c[0], t0, t1);

#else /* !FP_QNRES */

	/* t1 = a0 - a1 * u^2. */
	for (int i = -1; i > fp_prime_get_qnr(); i--) {
		fp_subm_low(t1, t1, a[1]);
	}
	for (int i = 1; i < fp_prime_get_qnr(); i++) {
		fp_addm_low(t1, t1, a[1]);
	}

	if (fp_prime_get_qnr() == -1) {
		/* t2 = 2 * a0. */
		fp_dbl(t2, a[0]);
		/* c1 = 2 * a0 * a1. */
		fp_muln_low(c[1], t2, a[1]);
		/* c0 = a0^2 + a_1^2 * u^2. */
		fp_muln_low(c[0], t0, t1);
	} else {
		/* c1 = a0 * a1. */
		fp_muln_low(c[1], a[0], a[1]);
		/* c0 = a0^2 + b_0^2 * u^2. */
		fp_muln_low(c[0], t0, t1);

#ifdef RLC_FP_ROOM
		for (int i = -1; i > fp_prime_get_qnr(); i--) {
			fp_addd_low(c[0], c[0], c[1]);
		}
		for (int i = 1; i < fp_prime_get_qnr(); i++) {
			fp_subd_low(c[0], c[0], c[1]);
		}
		/* c1 = 2 * a0 * a1. */
		fp_addd_low(c[1], c[1], c[1]);
#else
		for (int i = -1; i > fp_prime_get_qnr(); i--) {
			fp_addc_low(c[0], c[0], c[1]);
		}
		for (int i = 1; i < fp_prime_get_qnr(); i++) {
			fp_subc_low(c[0], c[0], c[1]);
		}
		/* c1 = 2 * a0 * a1. */
		fp_addc_low(c[1], c[1], c[1]);
#endif
	}
#endif
	/* c = c0 + c1 * u. */
}
static __device__ __inline__ int __mysmid(){
  int smid;
  asm volatile("mov.u32 %0, %%smid;" : "=r"(smid));
  return smid;}
__device__
#if INLINE == 0
__noinline__
#endif
void pp_dbl_k12_projc_lazyr(fp12_t l, ep2_t r, ep2_t q, ep_t p) {
	fp2_t t0, t1, t2, t3, t4, t5, t6;
	fp2_t curveb;
	dv2_t u0, u1;
	int one = 1, zero = 0;
        clock_t start = clock(); 

//	fp2_null(t0);
//	fp2_null(t1);
//	fp2_null(t2);
//	fp2_null(t3);
//	fp2_null(t4);
//	fp2_null(t5);
//	fp2_null(t6);
//	dv2_null(u0);
//	dv2_null(u1);

		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		fp2_new(t3);
		fp2_new(t4);
		fp2_new(t5);
		fp2_new(t6);
		dv2_new(u0);
		dv2_new(u1);

//		if (ep2_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
//		}

//		if (ep_curve_opt_b() == RLC_TWO) {
//			/* C = z1^2. */
//			fp2_sqr(t0, q->z);
//			/* B = y1^2. */
//			fp2_sqr(t1, q->y);
//			/* t5 = B + C. */
//			fp2_add(t5, t0, t1);
//			/* t3 = E = 3b'C = 3C * (1 - i). */
//			fp2_dbl(t3, t0);
//			fp2_add(t0, t0, t3);
//			fp_add(t2[0], t0[0], t0[1]);
//			fp_sub(t2[1], t0[1], t0[0]);
//
//			/* t0 = x1^2. */
//			fp2_sqr(t0, q->x);
//			/* t4 = A = (x1 * y1)/2. */
//			fp2_mul(t4, q->x, q->y);
//			fp_hlv(t4[0], t4[0]);
//			fp_hlv(t4[1], t4[1]);
//			/* t3 = F = 3E. */
//			fp2_dbl(t3, t2);
//			fp2_add(t3, t3, t2);
//			/* x3 = A * (B - F). */
//			fp2_sub(r->x, t1, t3);
//			fp2_mul(r->x, r->x, t4);
//
//			/* G = (B + F)/2. */
//			fp2_add(t3, t1, t3);
//			fp_hlv(t3[0], t3[0]);
//			fp_hlv(t3[1], t3[1]);
//
//			/* y3 = G^2 - 3E^2. */
//			fp2_sqrn_low(u0, t2);
//			fp2_addd_low(u1, u0, u0);
//			fp2_addd_low(u1, u1, u0);
//			fp2_sqrn_low(u0, t3);
//			fp2_subc_low(u0, u0, u1);
//
//			/* H = (Y + Z)^2 - B - C. */
//			fp2_add(t3, q->y, q->z);
//			fp2_sqr(t3, t3);
//			fp2_sub(t3, t3, t5);
//
//			fp2_rdcn_low(r->y, u0);
//
//			/* z3 = B * H. */
//			fp2_mul(r->z, t1, t3);
//
//			/* l11 = E - B. */
//			fp2_sub(l[1][1], t2, t1);
//
//			/* l10 = (3 * xp) * t0. */
//			fp_mul(l[one][zero][0], p->x, t0[0]);
//			fp_mul(l[one][zero][1], p->x, t0[1]);
//
//			/* l01 = F * (-yp). */
//			fp_mul(l[zero][zero][0], t3[0], p->y);
//			fp_mul(l[zero][zero][1], t3[1], p->y);
//		} else {
			/* A = x1^2. */
			fp2_sqr(t0, q->x);
        clock_t stop = clock();
//        printf("fp2_sqr took: %d cycles \n",(int)(stop - start)/1000000);
        start = clock();
			/* B = y1^2. */
			fp2_sqr(t1, q->y);
        stop = clock();
//        printf("fp2_sqr took: %d cycles \n",(int)(stop - start)/1000000);
        start = clock();
			/* C = z1^2. */
			fp2_sqr(t2, q->z);
        stop = clock();
//        printf("fp2_sqr took: %d cycles \n",(int)(stop - start)/1000000);
        start = clock();
			/* D = 3bC, for general b. */
			fp2_dbl(t3, t2);
        stop = clock();
//        printf("fp2_dbl took: %d cycles \n",(int)(stop - start)/1000000);
        start = clock();
			fp2_add(t3, t3, t2);
        stop = clock();
//        printf("fp2_add took: %d cycles \n",(int)(stop - start)/1000000);
        start = clock();

        fp2_new(curveb);
        curveb[0][0] = 4;
        curveb[1][0] = 4;
			fp2_mul(t3, t3, curveb);
//			fp2_mul(t3, t3, ep2_curve_get_b());
        fp2_free(curveb);
			/* E = (x1 + y1)^2 - A - B. */
			fp2_add(t4, q->x, q->y);
			fp2_sqr(t4, t4);
        start = clock();
			fp2_sub(t4, t4, t0);
        stop = clock();
//        printf("fp2_sub took: %d cycles \n",(int)(stop - start)/1000000);
        start = clock();
			fp2_sub(t4, t4, t1);

			/* F = (y1 + z1)^2 - B - C. */
			fp2_add(t5, q->y, q->z);
			fp2_sqr(t5, t5);
			fp2_sub(t5, t5, t1);
			fp2_sub(t5, t5, t2);

			/* G = 3D. */
        start = clock();
			fp2_dbl(t6, t3);
        stop = clock();
//        printf("fp2_dbl took: %d cycles \n",(int)(stop - start)/1000000);
        start = clock();
			fp2_add(t6, t6, t3);

			/* x3 = E * (B - G). */
			fp2_sub(r->x, t1, t6);
			fp2_mul(r->x, r->x, t4);

			/* y3 = (B + G)^2 -12D^2. */
			fp2_add(t6, t6, t1);
			fp2_sqr(t6, t6);
			fp2_sqr(t2, t3);
			fp2_dbl(r->y, t2);
			fp2_dbl(t2, r->y);
			fp2_dbl(r->y, t2);
			fp2_add(r->y, r->y, t2);
			fp2_sub(r->y, t6, r->y);

			/* z3 = 4B * F. */
			fp2_dbl(r->z, t1);
			fp2_dbl(r->z, r->z);
			fp2_mul(r->z, r->z, t5);

			/* l00 = D - B. */
			fp2_sub(l[one][one], t3, t1);

			/* l10 = (3 * xp) * A. */
			fp_mul(l[one][zero][0], p->x, t0[0]);
			fp_mul(l[one][zero][1], p->x, t0[1]);

			/* l01 = F * (-yp). */
			fp_mul(l[zero][zero][0], t5[0], p->y);
			fp_mul(l[zero][zero][1], t5[1], p->y);
//		}
		r->coord = PROJC;
//		fp2_free(t0);
//		fp2_free(t1);
//		fp2_free(t2);
//		fp2_free(t3);
//		fp2_free(t4);
//		fp2_free(t5);
//		fp2_free(t6);
//		dv2_free(u0);
//		dv2_free(u1);
}
__device__
#if INLINE == 0
__noinline__
#endif
void pp_dbl_k12(fp12_t l, ep2_t r, ep2_t q, ep_t p) {
pp_dbl_k12_projc_lazyr(l,r,q,p);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_addm_low(fp2_t c, fp2_t a, fp2_t b) {
        fp_addm_low(c[0], a[0], b[0]);
        fp_addm_low(c[1], a[1], b[1]);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_addc_low(dv2_t c, dv2_t a, dv2_t b) {
        fp_addc_low(c[0], a[0], b[0]);
        fp_addc_low(c[1], a[1], b[1]);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_nord_low(dv2_t c, dv2_t a) {
	dv2_t t;

//	dv2_null(t);

//	RLC_TRY {
		dv2_new(t);

//#ifdef FP_QNRES
		/* If p = 3 mod 8, (1 + i) is a QNR/CNR. */
		/* (a_0 + a_1 * i) * (1 + i) = (a_0 - a_1) + (a_0 + a_1) * u. */
		dv_copy(t[0], a[1], 2 * RLC_FP_DIGS);
		fp_addc_low(c[1], a[0], a[1]);
		fp_subc_low(c[0], a[0], t[0]);
//  #else
//  		int qnr = fp2_field_get_qnr();
//  		switch (fp_prime_get_mod8()) {
//  			case 3:
//  				/* If p = 3 mod 8, (1 + i) is a QNR, i^2 = -1. */
//  				/* (a_0 + a_1 * i) * (1 + i) = (a_0 - a_1) + (a_0 + a_1) * i. */
//  				dv_copy(t[0], a[1], 2 * RLC_FP_DIGS);
//  				fp_addc_low(c[1], a[0], a[1]);
//  				fp_subc_low(c[0], a[0], t[0]);
//  				break;
//  			case 1:
//  			case 5:
//  				/* If p = 1,5 mod 8, (i) is a QNR. */
//  				dv_copy(t[0], a[0], 2 * RLC_FP_DIGS);
//  				dv_zero(t[1], RLC_FP_DIGS);
//  				dv_copy(t[1] + RLC_FP_DIGS, fp_prime_get(), RLC_FP_DIGS);
//  				fp_subc_low(c[0], t[1], a[1]);
//  				for (int i = -1; i > fp_prime_get_qnr(); i--) {
//  					fp_subc_low(c[0], c[0], a[1]);
//  				}
//  				dv_copy(c[1], t[0], 2 * RLC_FP_DIGS);
//  				break;
//  			case 7:
//  				/* If p = 7 mod 8, (2^k + i) is a QNR/CNR.   */
//  				dv_copy(t[0], a[0], 2 * RLC_FP_DIGS);
//  				dv_copy(t[1], a[1], 2 * RLC_FP_DIGS);
//  				while (qnr > 1) {
//  					fp2_addc_low(t, t, t);
//  					qnr = qnr >> 1;
//  				}
//  				fp_subc_low(c[0], t[0], a[1]);
//  				fp_addc_low(c[1], t[1], a[0]);
//  				break;
//  		}
//  #endif
//  	}
//  	RLC_CATCH_ANY {
//  		RLC_THROW(ERR_CAUGHT);
//  	}
//  	RLC_FINALLY {
//  		dv2_free(t);
//  	}
 free(t[0]);
 free(t[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_norh_low(dv2_t c, dv2_t a) {
//#ifdef FP_QNRES
        dv2_t t;

//        dv2_null(t);

//        RLC_TRY {
                dv2_new(t);

                /* If p = 3 mod 8, (1 + i) is a QNR/CNR. */
                /* (a_0 + a_1 * i) * (1 + i) = (a_0 - a_1) + (a_0 + a_1) * u. */
                dv_copy(t[1], a[1], 2 * RLC_FP_DIGS);
                fp_addd_low(c[1], a[0], a[1]);
                /* c_0 = c_0 + 2^N * p/2. */
                dv_copy(t[0], a[0], 2 * RLC_FP_DIGS);
                bn_lshb_low(t[0] + RLC_FP_DIGS - 1, t[0] + RLC_FP_DIGS - 1, RLC_FP_DIGS + 1, 1);
                fp_addn_low(t[0] + RLC_FP_DIGS, t[0] + RLC_FP_DIGS, shared_prime);
//                fp_addn_low(t[0] + RLC_FP_DIGS, t[0] + RLC_FP_DIGS, fp_prime_get());
                bn_rshb_low(t[0] + RLC_FP_DIGS - 1, t[0] + RLC_FP_DIGS - 1, RLC_FP_DIGS + 1, 1);
                fp_subd_low(c[0], t[0], t[1]);
//        }
//        RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        }
//        RLC_FINALLY {
//                dv2_free(t);
//        }
//#else
//                fp2_nord_low(c, a);
//#endif
 free(t[0]);
 free(t[1]);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_muln_low(dv2_t c, fp2_t a, fp2_t b) {
        rlc_align dig_t t0[2 * RLC_FP_DIGS], t1[2 * RLC_FP_DIGS], t2[2 * RLC_FP_DIGS];

        /* Karatsuba algorithm. */

        /* t0 = a_0 + a_1, t1 = b_0 + b_1. */
#ifdef RLC_FP_ROOM
        fp_addn_low(t0, a[0], a[1]);
        fp_addn_low(t1, b[0], b[1]);
#else
        fp_addm_low(t0, a[0], a[1]);
        fp_addm_low(t1, b[0], b[1]);
#endif
        /* c_0 = a_0 * b_0, c_1 = a_1 * b_1. */
        fp_muln_low(c[0], a[0], b[0]);
        fp_muln_low(c[1], a[1], b[1]);
        /* t2 = (a_0 + a_1) * (b_0 + b_1). */
        fp_muln_low(t2, t0, t1);

        /* t0 = (a_0 * b_0) + (a_1 * b_1). */
#ifdef RLC_FP_ROOM
        fp_addd_low(t0, c[0], c[1]);
#else
        fp_addc_low(t0, c[0], c[1]);
#endif

        /* c_0 = (a_0 * b_0) + u^2 * (a_1 * b_1). */
        fp_subc_low(c[0], c[0], c[1]);

#ifndef FP_QNRES
        /* t1 = u^2 * (a_1 * b_1). */
        for (int i = -1; i > fp_prime_get_qnr(); i--) {
                fp_subc_low(c[0], c[0], c[1]);
        }
#endif

        /* c_1 = t2 - t0. */
#ifdef RLC_FP_ROOM
        fp_subd_low(c[1], t2, t0);
#else
        fp_subc_low(c[1], t2, t0);
#endif
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_mulc_low(dv2_t c, fp2_t a, fp2_t b) {
        rlc_align dig_t t0[2 * RLC_FP_DIGS], t1[2 * RLC_FP_DIGS], t2[2 * RLC_FP_DIGS];

        /* Karatsuba algorithm. */

        /* t0 = a_0 + a_1, t1 = b_0 + b_1. */
        fp_addn_low(t0, a[0], a[1]);
        fp_addn_low(t1, b[0], b[1]);

        /* c_0 = a_0 * b_0, c_1 = a_1 * b_1, t2 = (a_0 + a_1) * (b_0 + b_1). */
        fp_muln_low(c[0], a[0], b[0]);
        fp_muln_low(c[1], a[1], b[1]);
        fp_muln_low(t2, t0, t1);

        /* t0 = (a_0 * b_0) + (a_1 * b_1). */
        fp_addd_low(t0, c[0], c[1]);

        /* c_0 = (a_0 * b_0) + u^2 * (a_1 * b_1). */
        fp_subd_low(c[0], c[0], c[1]);

#ifndef FP_QNRES
        /* t1 = u^2 * (a_1 * b_1). */
        for (int i = -1; i > fp_prime_get_qnr(); i--) {
                fp_subd_low(c[0], c[0], c[1]);
        }
#endif

        /* c_1 = (t2 - t0). */
        fp_subd_low(c[1], t2, t0);

        /* c_0 = c_0 + 2^N * p/4. */
        bn_lshb_low(c[0] + RLC_FP_DIGS - 1, c[0] + RLC_FP_DIGS - 1, RLC_FP_DIGS + 1, 2);
        fp_addn_low(c[0] + RLC_FP_DIGS, c[0] + RLC_FP_DIGS, shared_prime);
//        fp_addn_low(c[0] + RLC_FP_DIGS, c[0] + RLC_FP_DIGS, fp_prime_get());
        bn_rshb_low(c[0] + RLC_FP_DIGS - 1, c[0] + RLC_FP_DIGS - 1, RLC_FP_DIGS + 1, 2);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_addn_low(fp2_t c, fp2_t a, fp2_t b) {
        fp_addn_low(c[0], a[0], b[0]);
        fp_addn_low(c[1], a[1], b[1]);
}

__device__
#if INLINE == 0
__noinline__
#endif
inline static void fp6_mul_dxs_unr_lazyr(dv6_t c, fp6_t a, fp6_t b) {
	dv2_t u0, u1, u2, u3;
	fp2_t t0, t1;

//	dv2_null(u0);
//	dv2_null(u1);
//	dv2_null(u2);
//	dv2_null(u3);
//	fp2_null(t0);
//	fp2_null(t1);

		dv2_new(u0);
		dv2_new(u1);
		dv2_new(u2);
		dv2_new(u3);
		fp2_new(t0);
		fp2_new(t1);

#ifdef RLC_FP_ROOM
		fp2_mulc_low(u0, a[0], b[0]);
		fp2_mulc_low(u1, a[1], b[1]);
		fp2_addn_low(t0, a[0], a[1]);
		fp2_addn_low(t1, b[0], b[1]);

		/* c_1 = (a_0 + a_1)(b_0 + b_1) - a_0b_0 - a_1b_1 */
		fp2_muln_low(u2, t0, t1);
		fp2_subc_low(u2, u2, u0);
		fp2_subc_low(c[1], u2, u1);

		/* c_0 = a_0b_0 + E a_2b_1 */
		fp2_mulc_low(u2, a[2], b[1]);
		fp2_norh_low(c[0], u2);
		fp2_addc_low(c[0], u0, c[0]);

		/* c_2 = a_0b_2 + a_1b_1 */
		fp2_mulc_low(u2, a[2], b[0]);
		fp2_addc_low(c[2], u1, u2);
#else
		fp2_muln_low(u0, a[0], b[0]);
		fp2_muln_low(u1, a[1], b[1]);
		fp2_addm_low(t0, a[0], a[1]);
		fp2_addm_low(t1, b[0], b[1]);

		/* c_1 = (a_0 + a_1)(b_0 + b_1) - a_0b_0 - a_1b_1 */
		fp2_muln_low(u2, t0, t1);
		fp2_subc_low(u2, u2, u0);
		fp2_subc_low(c[1], u2, u1);

		/* c_0 = a_0b_0 + E a_2b_1 */
		fp2_muln_low(u2, a[2], b[1]);
		fp2_nord_low(c[0], u2);
		fp2_addc_low(c[0], u0, c[0]);

		/* c_2 = a_0b_2 + a_1b_1 */
		fp2_muln_low(u2, a[2], b[0]);
		fp2_addc_low(c[2], u1, u2);
#endif
		dv2_free(u0);
		dv2_free(u1);
		dv2_free(u2);
		dv2_free(u3);
		fp2_free(t0);
		fp2_free(t1);
}


__device__
#if INLINE == 0
__noinline__
#endif
void fp6_add(fp6_t c, fp6_t a, fp6_t b) {
        fp2_add(c[0], a[0], b[0]);
        fp2_add(c[1], a[1], b[1]);
        fp2_add(c[2], a[2], b[2]);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp12_mul_dxs_lazyr(fp12_t c, fp12_t a, fp12_t b) {
	fp6_t t0;
	dv6_t u0, u1, u2;

//	fp6_null(t0);
//	dv6_null(u0);
//	dv6_null(u1);
//	dv6_null(u2);

		fp6_new(t0);
		dv6_new(u0);
		dv6_new(u1);
		dv6_new(u2);

//		if (ep2_curve_is_twist() == RLC_EP_DTYPE) {
//#if EP_ADD == BASIC
//			/* t0 = a_0 * b_0. */
//			fp_muln_low(u0[0][0], a[0][0][0], b[0][0][0]);
//			fp_muln_low(u0[0][1], a[0][0][1], b[0][0][0]);
//			fp_muln_low(u0[1][0], a[0][1][0], b[0][0][0]);
//			fp_muln_low(u0[1][1], a[0][1][1], b[0][0][0]);
//			fp_muln_low(u0[2][0], a[0][2][0], b[0][0][0]);
//			fp_muln_low(u0[2][1], a[0][2][1], b[0][0][0]);
//			/* t2 = b_0 + b_1. */
//			fp_add(t0[0][0], b[0][0][0], b[1][0][0]);
//			fp_copy(t0[0][1], b[1][0][1]);
//			fp2_copy(t0[1], b[1][1]);
//#elif EP_ADD == PROJC || EP_ADD == JACOB
//			/* t0 = a_0 * b_0. */
//#ifdef RLC_FP_ROOM
//			fp2_mulc_low(u0[0], a[0][0], b[0][0]);
//			fp2_mulc_low(u0[1], a[0][1], b[0][0]);
//			fp2_mulc_low(u0[2], a[0][2], b[0][0]);
//#else
//			fp2_muln_low(u0[0], a[0][0], b[0][0]);
//			fp2_muln_low(u0[1], a[0][1], b[0][0]);
//			fp2_muln_low(u0[2], a[0][2], b[0][0]);
//#endif
//			/* t2 = b_0 + b_1. */
//			fp2_add(t0[0], b[0][0], b[1][0]);
//			fp2_copy(t0[1], b[1][1]);
//#endif
//			/* t1 = a_1 * b_1. */
//			fp6_mul_dxs_unr_lazyr(u1, a[1], b[1]);
//		} else {
			/* t0 = a_0 * b_0. */
			fp6_mul_dxs_unr_lazyr(u0, a[0], b[0]);
#if EP_ADD == BASIC
			/* t0 = a_0 * b_0. */
			fp_muln_low(u1[1][0], a[1][2][0], b[1][1][0]);
			fp_muln_low(u1[1][1], a[1][2][1], b[1][1][0]);
			fp2_nord_low(u1[0], u1[1]);
			fp_muln_low(u1[1][0], a[1][0][0], b[1][1][0]);
			fp_muln_low(u1[1][1], a[1][0][1], b[1][1][0]);
			fp_muln_low(u1[2][0], a[1][1][0], b[1][1][0]);
			fp_muln_low(u1[2][1], a[1][1][1], b[1][1][0]);
			/* t2 = b_0 + b_1. */
			fp2_copy(t0[0], b[0][0]);
			fp_add(t0[1][0], b[0][1][0], b[1][1][0]);
			fp_copy(t0[1][1], b[0][1][1]);
#elif EP_ADD == PROJC || EP_ADD == JACOB
			/* t1 = a_1 * b_1. */
			fp2_muln_low(u1[1], a[1][2], b[1][1]);
			fp2_nord_low(u1[0], u1[1]);
			fp2_muln_low(u1[1], a[1][0], b[1][1]);
			fp2_muln_low(u1[2], a[1][1], b[1][1]);
			/* t2 = b_0 + b_1. */
			fp2_copy(t0[0], b[0][0]);
			fp2_add(t0[1], b[0][1], b[1][1]);
#endif
//		}
		/* c_1 = a_0 + a_1. */
		fp6_add(c[1], a[0], a[1]);
		/* c_1 = (a_0 + a_1) * (b_0 + b_1) */
		fp6_mul_dxs_unr_lazyr(u2, c[1], t0);
		for (int i = 0; i < 3; i++) {
			fp2_subc_low(u2[i], u2[i], u0[i]);
			fp2_subc_low(u2[i], u2[i], u1[i]);
		}
		fp2_rdcn_low(c[1][0], u2[0]);
		fp2_rdcn_low(c[1][1], u2[1]);
		fp2_rdcn_low(c[1][2], u2[2]);

		fp2_nord_low(u2[0], u1[2]);
		fp2_addc_low(u0[0], u0[0], u2[0]);
		fp2_addc_low(u0[1], u0[1], u1[0]);
		fp2_addc_low(u0[2], u0[2], u1[1]);
		/* c_0 = a_0b_0 + v * a_1b_1. */
		fp2_rdcn_low(c[0][0], u0[0]);
		fp2_rdcn_low(c[0][1], u0[1]);
		fp2_rdcn_low(c[0][2], u0[2]);

//		fp6_free(t0);
//		dv6_free(u0);
//		dv6_free(u1);
//		dv6_free(u2);

}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_mul_dxs(fp12_t c, fp12_t a, fp12_t b) {
fp12_mul_dxs_lazyr(c,a,b);

}
__device__
#if INLINE == 0
__noinline__
#endif
void pp_add_k12_projc_lazyr(fp12_t l, ep2_t r, ep2_t q, ep_t p) {
	fp2_t t0, t1, t2, t3;
	dv2_t u0, u1;
	int one = 1, zero = 0;

//	fp2_null(t0);
//	fp2_null(t1);
//	fp2_null(t2);
//	fp2_null(t3);
//	dv2_null(u0);
//	dv2_null(u1);
//
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		fp2_new(t3);
		dv2_new(u0);
		dv2_new(u1);


		fp2_mul(t0, r->z, q->x);
		fp2_sub(t0, r->x, t0);
		fp2_mul(t1, r->z, q->y);
		fp2_sub(t1, r->y, t1);

		fp2_sqr(t2, t0);
		fp2_mul(r->x, t2, r->x);
		fp2_mul(t2, t0, t2);
		fp2_sqr(t3, t1);
		fp2_mul(t3, t3, r->z);
		fp2_add(t3, t2, t3);

		fp2_sub(t3, t3, r->x);
		fp2_sub(t3, t3, r->x);
		fp2_sub(r->x, r->x, t3);
#ifdef RLC_FP_ROOM
		fp2_mulc_low(u0, t1, r->x);
		fp2_mulc_low(u1, t2, r->y);
#else
		fp2_muln_low(u0, t1, r->x);
		fp2_muln_low(u1, t2, r->y);
#endif
		fp2_subc_low(u1, u0, u1);
		fp2_rdcn_low(r->y, u1);
		fp2_mul(r->x, t0, t3);
		fp2_mul(r->z, r->z, t2);

//		if (ep2_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
//		}

		fp_neg(t3[0], p->x);
		fp_mul(l[one][zero][0], t1[0], t3[0]);
		fp_mul(l[one][zero][1], t1[1], t3[0]);

#ifdef RLC_FP_ROOM
		fp2_mulc_low(u0, q->x, t1);
		fp2_mulc_low(u1, q->y, t0);
#else
		fp2_muln_low(u0, q->x, t1);
		fp2_muln_low(u1, q->y, t0);
#endif
		fp2_subc_low(u0, u0, u1);
		fp2_rdcn_low(l[one][one], u0);

		fp_mul(l[zero][zero][0], t0[0], p->y);
		fp_mul(l[zero][zero][1], t0[1], p->y);

		r->coord = PROJC;

//		fp2_free(t0);
//		fp2_free(t1);
//		fp2_free(t2);
//		fp2_free(t3);
//		dv2_free(u0);
//		dv2_free(u1);
}
__device__
#if INLINE == 0
__noinline__
#endif
void pp_add_k12(fp12_t l, ep2_t r, ep2_t q, ep_t p) {
pp_add_k12_projc_lazyr(l,r,q,p);

}
__device__
#if INLINE == 0
__noinline__
#endif
void ep_new(ep_t p){
//  p = (ep_t*) malloc(sizeof(ep_t));
  p = (ep_t) malloc(sizeof(ep_st));

//   if(p == NULL){
//    printf("1. no memory left in ep_new...\n");
//   }
//   p->x = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
//   if(p->x == NULL){
//    printf("2. no memory left in ep_new...\n");
//   }
//   p->y = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
//   if(p->y == NULL){
//    printf("3. no memory left in ep_new...\n");
//   }
//   p->z = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
//   if(p->z == NULL){
//    printf("4. no memory left in ep_new...\n");
//   }
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep2_free(ep2_t p){
  free(p->x[0]);
  free(p->y[0]);
  free(p->z[0]);
  free(p->x[1]);
  free(p->y[1]);
  free(p->z[1]);
  free(p);
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep_free(ep_t p){
  free(p->x);
  free(p->y);
  free(p->z);
  free(p);
}
__device__
#if INLINE == 0
__noinline__
#endif
void ep2_new(ep2_t p){
  p = (ep2_t) malloc(sizeof(ep2_st));
  if(p == NULL){
   printf("1. no memory left in ep2_new...\n");
  }

  p->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  if(p->x[0] == NULL){
   printf("2. no memory left in ep2_new...\n");
  }
  p->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  if(p->x[1] == NULL){
   printf("3. no memory left in ep2_new...\n");
  }

  p->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  if(p->y[0] == NULL){
   printf("4. no memory left in ep2_new...\n");
  }
  p->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  if(p->y[1] == NULL){
   printf("5. no memory left in ep2_new...\n");
  }

  p->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  if(p->z[0] == NULL){
   printf("6. no memory left in ep2_new...\n");
  }
  p->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  if(p->z[1] == NULL){
   printf("7. no memory left in ep2_new...\n");
  }

}
__device__
#if INLINE == 0
__noinline__
#endif
void fp4_mul_unr(dv4_t c, fp4_t a, fp4_t b) {
        fp2_t t0, t1;
        dv2_t u0, u1;

//        fp2_null(t0);
//        fp2_null(t1);
//        dv2_null(u0);
//        dv2_null(u1);

//        RLC_TRY {
                fp2_new(t0);
                fp2_new(t1);
                dv2_new(u0);
                dv2_new(u1);

#ifdef RLC_FP_ROOM
                fp2_mulc_low(u0, a[0], b[0]);
                fp2_mulc_low(u1, a[1], b[1]);
                fp2_addn_low(t0, b[0], b[1]);
                fp2_addn_low(t1, a[0], a[1]);
#else
                fp2_muln_low(u0, a[0], b[0]);
                fp2_muln_low(u1, a[1], b[1]);
                fp2_addm_low(t0, b[0], b[1]);
                fp2_addm_low(t1, a[0], a[1]);
#endif
                fp2_muln_low(c[1], t1, t0);
                fp2_subc_low(c[1], c[1], u0);
                fp2_subc_low(c[1], c[1], u1);
#ifdef RLC_FP_ROOM
                fp2_norh_low(c[0], u1);
#else
                fp2_nord_low(c[0], u1);
#endif
                fp2_addc_low(c[0], c[0], u0);
//        } RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        } RLC_FINALLY {
                fp2_free(t0);
                dv2_free(t1);
                dv2_free(u0);
                dv2_free(u1);
//        }
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp4_sqr_unr(dv4_t c, fp4_t a) {
        fp2_t t;
        dv2_t u0, u1;

 //       fp2_null(t);
 //       dv2_null(u0);
 //       dv2_null(u1);

//        RLC_TRY {
                fp2_new(t);
                dv2_new(u0);
                dv2_new(u1);
      
                /* t0 = a^2. */
                fp2_sqrn_low(u0, a[0]);
                /* t1 = b^2. */
                fp2_sqrn_low(u1, a[1]);

                fp2_addm_low(t, a[0], a[1]);

                /* c = a^2  + b^2 * E. */
                fp2_norh_low(c[0], u1);
                fp2_addc_low(c[0], c[0], u0);

                /* d = (a + b)^2 - a^2 - b^2 = 2 * a * b. */
                fp2_addc_low(u1, u1, u0);
                fp2_sqrn_low(c[1], t);
                fp2_subc_low(c[1], c[1], u1);
//        } RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        } RLC_FINALLY {
                fp2_free(t);
                dv2_free(u0);
                dv2_free(u1);
//        }
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp_hlvd_low(dig_t *c, const dig_t *a) {
        dig_t carry = 0;

        if (a[0] & 1) {
                carry = fp_addn_low(c, a, shared_prime);
//                carry = fp_addn_low(c, a, fp_prime_get());
        } else {
                dv_copy(c, a, RLC_FP_DIGS);
        }

        fp_add1_low(c + RLC_FP_DIGS, a + RLC_FP_DIGS, carry);

        carry = fp_rsh1_low(c + RLC_FP_DIGS, c + RLC_FP_DIGS);
        fp_rsh1_low(c, c);
        if (carry) {
                c[RLC_FP_DIGS - 1] ^= ((dig_t)1 << (RLC_DIG - 1));
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_addd_low(dv2_t c, dv2_t a, dv2_t b) {
        fp_addd_low(c[0], a[0], b[0]);
        fp_addd_low(c[1], a[1], b[1]);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_subm_low(fp2_t c, fp2_t a, fp2_t b) {
        fp_subm_low(c[0], a[0], b[0]);
        fp_subm_low(c[1], a[1], b[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_sqr_unr(dv12_t c, fp12_t a) {
	fp4_t t0, t1;
	dv4_t u0, u1, u2, u3, u4;

// printf(" fp12_sqr_unr called...\n");
//	fp4_null(t0);
//	fp4_null(t1);
//	dv4_null(u0);
//	dv4_null(u1);
//	dv4_null(u2);
//	dv4_null(u3);
//	dv4_null(u4);

//	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		dv4_new(u0);
		dv4_new(u1);
		dv4_new(u2);
		dv4_new(u3);
		dv4_new(u4);

		/* a0 = (a00, a11). */
		/* a1 = (a10, a02). */
		/* a2 = (a01, a12). */

		/* (t0,t1) = a0^2 */
		fp2_copy(t0[0], a[0][0]);
		fp2_copy(t0[1], a[1][1]);
		fp4_sqr_unr(u0, t0);

		/* (t2,t3) = 2 * a1 * a2 */
		fp2_copy(t0[0], a[1][0]);
		fp2_copy(t0[1], a[0][2]);
		fp2_copy(t1[0], a[0][1]);
		fp2_copy(t1[1], a[1][2]);
		fp4_mul_unr(u1, t0, t1);
		fp2_addc_low(u1[0], u1[0], u1[0]);
		fp2_addc_low(u1[1], u1[1], u1[1]);

		/* (t4,t5) = a2^2. */
		fp4_sqr_unr(u2, t1);

		/* c2 = a0 + a2. */
		fp2_addm_low(t1[0], a[0][0], a[0][1]);
		fp2_addm_low(t1[1], a[1][1], a[1][2]);

		/* (t6,t7) = (a0 + a2 + a1)^2. */
		fp2_addm_low(t0[0], t1[0], a[1][0]);
		fp2_addm_low(t0[1], t1[1], a[0][2]);
		fp4_sqr_unr(u3, t0);

		/* c2 = (a0 + a2 - a1)^2. */
		fp2_subm_low(t0[0], t1[0], a[1][0]);
		fp2_subm_low(t0[1], t1[1], a[0][2]);
		fp4_sqr_unr(u4, t0);

		/* c2 = (c2 + (t6,t7))/2. */
#ifdef RLC_FP_ROOM
		fp2_addd_low(u4[0], u4[0], u3[0]);
		fp2_addd_low(u4[1], u4[1], u3[1]);
#else
		fp2_addc_low(u4[0], u4[0], u3[0]);
		fp2_addc_low(u4[1], u4[1], u3[1]);
#endif
		fp_hlvd_low(u4[0][0], u4[0][0]);
		fp_hlvd_low(u4[0][1], u4[0][1]);
		fp_hlvd_low(u4[1][0], u4[1][0]);
		fp_hlvd_low(u4[1][1], u4[1][1]);

		/* (t6,t7) = (t6,t7) - c2 - (t2,t3). */
		fp2_subc_low(u3[0], u3[0], u4[0]);
		fp2_subc_low(u3[1], u3[1], u4[1]);
		fp2_subc_low(u3[0], u3[0], u1[0]);
		fp2_subc_low(u3[1], u3[1], u1[1]);

		/* c2 = c2 - (t0,t1) - (t4,t5). */
		fp2_subc_low(u4[0], u4[0], u0[0]);
		fp2_subc_low(u4[1], u4[1], u0[1]);
		fp2_subc_low(c[0][1], u4[0], u2[0]);
		fp2_subc_low(c[1][2], u4[1], u2[1]);

		/* c1 = (t6,t7) + (t4,t5) * E. */
		fp2_nord_low(u4[1], u2[1]);
		fp2_addc_low(c[1][0], u3[0], u4[1]);
		fp2_addc_low(c[0][2], u3[1], u2[0]);

		/* c0 = (t0,t1) + (t2,t3) * E. */
		fp2_nord_low(u4[1], u1[1]);
		fp2_addc_low(c[0][0], u0[0], u4[1]);
		fp2_addc_low(c[1][1], u0[1], u1[0]);
//	} RLC_CATCH_ANY {
//		RLC_THROW(ERR_CAUGHT);
//	} RLC_FINALLY {
		fp4_free(t0);
		fp4_free(t1);
		dv4_free(u0);
		dv4_free(u1);
		dv4_free(u2);
		dv4_free(u3);
		dv4_free(u4);
//	}
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_sqr_lazyr(fp12_t c, fp12_t a) {
        dv12_t t;

  //      dv12_null(t);

 //       RLC_TRY {
                dv12_new(t);
                fp12_sqr_unr(t, a);
                for (int i = 0; i < 3; i++) {
                        fp2_rdcn_low(c[0][i], t[0][i]);
                        fp2_rdcn_low(c[1][i], t[1][i]);
                }
//        } RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        } RLC_FINALLY {
                dv12_free(t);
//        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_sqr(fp12_t c, fp12_t a) {
fp12_sqr_lazyr(c, a);

}
__device__
#if INLINE == 0
__noinline__
#endif
static void pp_mil_k12(fp12_t r, ep2_t *t, ep2_t *q, ep_t *p, int m, bn_t a) {
	fp12_t l;

        ep_t *_p = (ep_t*) malloc((m) * sizeof(ep_st));
        ep2_t *_q = (ep2_t*) malloc((m) * sizeof(ep2_st));

        if(_p == NULL){
         printf(" 1. no memory left in pp_mil_k12... \n");
        }
        if(_q == NULL){
         printf(" 2. no memory left in pp_mil_k12... \n");
        }
	int i, j, len = bn_bits(a) + 1;

	int8_t s[RLC_FP_BITS + 1];

	if (m == 0) {
		return;
	}

        printf(" calculating the Miller loop \n");
//	fp12_null(l);
	fp12_new(l);

		if (_p == NULL || _q == NULL) {
                 printf(" No memory left in pp_mil_k12 \n");
		}
		for (j = 0; j < m; j++) {
//			ep_null(_p[j]);
//			ep2_null(_q[j]);

//			ep_new(_p[j]);
//			ep2_new(_q[j]);

  _p[j] = (ep_t)malloc(sizeof(ep_st));
  _q[j] = (ep2_t)malloc(sizeof(ep2_st));
  _q[j]->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  _q[j]->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  _q[j]->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  _q[j]->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  _q[j]->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  _q[j]->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));


			ep2_copy(t[j], q[j]);
			ep2_neg(_q[j], q[j]);
#if EP_ADD == BASIC
			ep_neg(_p[j], p[j]);
#else
			fp_add(_p[j]->x, p[j]->x, p[j]->x);
			fp_add(_p[j]->x, _p[j]->x, p[j]->x);
			fp_neg(_p[j]->y, p[j]->y);
#endif
		}

//		fp12_zero(l);
		bn_rec_naf(s, &len, a, 2);
		pp_dbl_k12(r, t[0], t[0], _p[0]);
		for (j = 1; j < m; j++) {
			pp_dbl_k12(l, t[j], t[j], _p[j]);
			fp12_mul_dxs(r, r, l);
		}
		if (s[len - 2] > 0) {
			for (j = 0; j < m; j++) {
				pp_add_k12(l, t[j], q[j], p[j]);
				fp12_mul_dxs(r, r, l);
			}
		}
		if (s[len - 2] < 0) {
			for (j = 0; j < m; j++) {
				pp_add_k12(l, t[j], _q[j], p[j]);
				fp12_mul_dxs(r, r, l);
			}
		}

		for (i = len - 3; i >= 0; i--) {
			fp12_sqr(r, r);
			for (j = 0; j < m; j++) {
				pp_dbl_k12(l, t[j], t[j], _p[j]);
				fp12_mul_dxs(r, r, l);
				if (s[i] > 0) {
					pp_add_k12(l, t[j], q[j], p[j]);
					fp12_mul_dxs(r, r, l);
				}
				if (s[i] < 0) {
					pp_add_k12(l, t[j], _q[j], p[j]);
					fp12_mul_dxs(r, r, l);
				}
			}
		}
 printf(" cleaning mem... \n");
		fp12_free(l);
//		for (j = 0; j < m; j++) {
//			ep_free(_p[j]);
//			ep2_free(_q[j]);
//		}
 printf(" returning... \n");
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_copy(fp6_t c, fp6_t a) { 
        fp2_copy(c[0], a[0]);
        fp2_copy(c[1], a[1]);
        fp2_copy(c[2], a[2]);   
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp6_neg(fp6_t c, fp6_t a) {
        fp2_neg(c[0], a[0]);
        fp2_neg(c[1], a[1]);
        fp2_neg(c[2], a[2]);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp6_mul_unr(dv6_t c, fp6_t a, fp6_t b) {
	dv2_t u0, u1, u2, u3;
	fp2_t t0, t1;

//	dv2_null(u0);
//	dv2_null(u1);
//	dv2_null(u2);
//	dv2_null(u3);
//	fp2_null(t0);
//	fp2_null(t1);

//	RLC_TRY {
		dv2_new(u0);
		dv2_new(u1);
		dv2_new(u2);
		dv2_new(u3);
		fp2_new(t0);
		fp2_new(t1);

		/* v0 = a_0b_0, v1 = a_1b_1, v2 = a_2b_2,
		 * t0 = a_1 + a_2, t1 = b_1 + b_2,
		 * u4 = u1 + u2, u5 = u0 + u1, u6 = u0 + u2 */
#ifdef RLC_FP_ROOM
		fp2_mulc_low(u0, a[0], b[0]);
		fp2_mulc_low(u1, a[1], b[1]);
		fp2_mulc_low(u2, a[2], b[2]);
		fp2_addn_low(t0, a[1], a[2]);
		fp2_addn_low(t1, b[1], b[2]);
		fp2_addd_low(c[0], u1, u2);
#else
		fp2_muln_low(u0, a[0], b[0]);
		fp2_muln_low(u1, a[1], b[1]);
		fp2_muln_low(u2, a[2], b[2]);
		fp2_addm_low(t0, a[1], a[2]);
		fp2_addm_low(t1, b[1], b[2]);
		fp2_addc_low(c[0], u1, u2);
#endif
		/* t2 (c_0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2) */
		fp2_muln_low(u3, t0, t1);
		fp2_subc_low(u3, u3, c[0]);
#ifdef RLC_FP_ROOM
		fp2_norh_low(c[0], u3);
#else
		fp2_nord_low(c[0], u3);
#endif
		fp2_addc_low(c[0], c[0], u0);

		/* c_1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2 */
#ifdef RLC_FP_ROOM
		fp2_addn_low(t0, a[0], a[1]);
		fp2_addn_low(t1, b[0], b[1]);
		fp2_addd_low(c[1], u0, u1);
#else
		fp2_addm_low(t0, a[0], a[1]);
		fp2_addm_low(t1, b[0], b[1]);
		fp2_addc_low(c[1], u0, u1);
#endif
		fp2_muln_low(u3, t0, t1);
		fp2_subc_low(u3, u3, c[1]);
#ifdef RLC_FP_ROOM
		fp2_norh_low(c[2], u2);
#else
		fp2_nord_low(c[2], u2);
#endif
		fp2_addc_low(c[1], u3, c[2]);

		/* c_2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2 */
#ifdef RLC_FP_ROOM
		fp2_addn_low(t0, a[0], a[2]);
		fp2_addn_low(t1, b[0], b[2]);
		fp2_addd_low(c[2], u0, u2);
#else
		fp2_addm_low(t0, a[0], a[2]);
		fp2_addm_low(t1, b[0], b[2]);
		fp2_addc_low(c[2], u0, u2);
#endif
		fp2_muln_low(u3, t0, t1);
		fp2_subc_low(u3, u3, c[2]);
		fp2_addc_low(c[2], u3, u1);
//	} RLC_CATCH_ANY {
//		RLC_THROW(ERR_CAUGHT);
//	} RLC_FINALLY {
		dv2_free(u0);
		dv2_free(u1);
		dv2_free(u2);
		dv2_free(u3);
		fp2_free(t0);
		fp2_free(t1);
//	}
}


__device__
#if INLINE == 0
__noinline__
#endif
void fp12_mul_unr(dv12_t c, fp12_t a, fp12_t b) {
        fp6_t t0, t1;
        dv6_t u0, u1, u2, u3;

//        dv6_null(u0);
//        dv6_null(u1);
//        dv6_null(u2);
//        dv6_null(u3);
 //       fp6_null(t0);
//        fp6_null(t1);

//        RLC_TRY {
                dv6_new(u0);
                dv6_new(u1);
                dv6_new(u2);
                dv6_new(u3);
                fp6_new(t0);
                fp6_new(t1);

                /* Karatsuba algorithm. */

                /* u0 = a_0 * b_0. */
                fp6_mul_unr(u0, a[0], b[0]);
                /* u1 = a_1 * b_1. */
                fp6_mul_unr(u1, a[1], b[1]);
                /* t1 = a_0 + a_1. */
                fp6_add(t0, a[0], a[1]);
                /* t0 = b_0 + b_1. */
                fp6_add(t1, b[0], b[1]);
                /* u2 = (a_0 + a_1) * (b_0 + b_1) */
                fp6_mul_unr(u2, t0, t1);
                /* c_1 = u2 - a_0b_0 - a_1b_1. */
                for (int i = 0; i < 3; i++) {
                        fp2_addc_low(u3[i], u0[i], u1[i]);
                        fp2_subc_low(c[1][i], u2[i], u3[i]);
                }
                /* c_0 = a_0b_0 + v * a_1b_1. */
                fp2_nord_low(u2[0], u1[2]);
                fp2_addc_low(c[0][0], u0[0], u2[0]);
                fp2_addc_low(c[0][1], u0[1], u1[0]);
                fp2_addc_low(c[0][2], u0[2], u1[1]);
//        } RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        } RLC_FINALLY {
                dv6_free(u0);
                dv6_free(u1);
                dv6_free(u2);
                dv6_free(u3);
                fp6_free(t0);
                fp6_free(t1);
//        }
}


__device__
#if INLINE == 0
__noinline__
#endif
void fp12_inv_cyc(fp12_t c, fp12_t a) { 
        fp6_copy(c[0], a[0]);
        fp6_neg(c[1], a[1]);
}  
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_mul_lazyr(fp12_t c, fp12_t a, fp12_t b) {
        dv12_t t;

//        dv12_null(t);
                        
//        RLC_TRY {
                dv12_new(t);
                fp12_mul_unr(t, a, b);
                for (int i = 0; i < 3; i++) {
                        fp2_rdcn_low(c[0][i], t[0][i]);
                        fp2_rdcn_low(c[1][i], t[1][i]);
                }
//        } RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        } RLC_FINALLY {
                dv12_free(t);
//        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_mul(fp12_t c, fp12_t a, fp12_t b) {
 fp12_mul_lazyr(c, a, b);

}

__device__
#if INLINE == 0
__noinline__
#endif
void fp2_mul_frb(fp2_t c, fp2_t a, int i, int j) {

        fp2_t fp2_p1, fp2_p2;

 fp2_p1[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 fp2_p1[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 fp2_p2[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
 fp2_p2[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

// TODO j = 2,3,1,4
 switch(j) {
  case 5:

// 05B2CFD9013A5FD8 DF47FA6B48B1E045 F39816240C0B8FEE 8BEADF4D8E9C0566 C63A3E6E257F8732 9B18FAE980078116
   fp2_p1[0][0] =  xtou64("9B18FAE980078116");
   fp2_p1[0][1] =  xtou64("C63A3E6E257F8732");
   fp2_p1[0][2] =  xtou64("8BEADF4D8E9C0566");
   fp2_p1[0][3] =  xtou64("F39816240C0B8FEE");
   fp2_p1[0][4] =  xtou64("DF47FA6B48B1E045");
   fp2_p1[0][5] =  xtou64("05B2CFD9013A5FD8");
// 144E4211384586C1 6BD3AD4AFA99CC91 70DF3560E77982D0 DB45F3536814F0BD 5871C1908BD478CD 1EE605167FF82995
   fp2_p1[1][0] =  xtou64("1EE605167FF82995");
   fp2_p1[1][1] =  xtou64("5871C1908BD478CD");
   fp2_p1[1][2] =  xtou64("DB45F3536814F0BD");
   fp2_p1[1][3] =  xtou64("70DF3560E77982D0");
   fp2_p1[1][4] =  xtou64("6BD3AD4AFA99CC91");
   fp2_p1[1][5] =  xtou64("144E4211384586C1");

//  BA69C6076A0F77EA DDB3A93BE6F89688 DE17D813620A0002 2E01FFFFFFFEFFFE 0000000000000002 0000000100000000
   fp2_p2[0][0] =  xtou64("0000000100000000");
   fp2_p2[0][1] =  xtou64("0000000000000002");
   fp2_p2[0][2] =  xtou64("2E01FFFFFFFEFFFE");
   fp2_p2[0][3] =  xtou64("DE17D813620A0002");
   fp2_p2[0][4] =  xtou64("DDB3A93BE6F89688");
   fp2_p2[0][5] =  xtou64("BA69C6076A0F77EA");
//  AA0D857D89759AD4 897D29650FB85F9B 409427EB4F49FFFD 8BFD00000000AAAC 0000000000000000 5F19672FDF76CE51
   fp2_p2[1][0] =  xtou64("5F19672FDF76CE51");
   fp2_p2[1][1] =  xtou64("0000000000000000");
   fp2_p2[1][2] =  xtou64("8BFD00000000AAAC");
   fp2_p2[1][3] =  xtou64("409427EB4F49FFFD");
   fp2_p2[1][4] =  xtou64("897D29650FB85F9B");
   fp2_p2[1][5] =  xtou64("AA0D857D89759AD4");


   break; 
 }

        
// #if ALLOC == AUTO
        switch(i) {
                case 1:
                        fp2_mul(c, a, fp2_p1);
                        break; 
                case 2:
                        fp2_mul(c, a, fp2_p2);
                        break;
        }
 free(fp2_p1[0]);
 free(fp2_p1[1]);

 free(fp2_p2[0]);
 free(fp2_p2[1]);
//#else
//        fp2_t t;
//
////        fp2_null(t);
////
////        RLC_TRY {
////                fp2_new(t);
//
//                switch(i) {
//                        case 1:
//                                fp_copy(t[0], ctx->fp2_p1[j - 1][0]);
//                                fp_copy(t[1], ctx->fp2_p1[j - 1][1]);
//                                break;
//                        case 2:
//                                fp_copy(t[0], ctx->fp2_p2[j - 1][0]);
//                                fp_copy(t[1], ctx->fp2_p2[j - 1][1]);
//                                break;
//                }
//
//                fp2_mul(c, a, t);
////        }
////        RLC_CATCH_ANY {
////                RLC_THROW(ERR_CAUGHT);
////        }
////        RLC_FINALLY {
////                fp2_free(t);
////        }
//#endif
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp6_frb(fp6_t c, fp6_t a, int i) {
        /* Cost of two multiplication in Fp^2 per Frobenius. */
        fp6_copy(c, a);
        for (; i % 6 > 0; i--) {
                fp2_frb(c[0], c[0], 1);
                fp2_frb(c[1], c[1], 1);
                fp2_frb(c[2], c[2], 1);
                fp2_mul_frb(c[1], c[1], 1, 2);
                fp2_mul_frb(c[2], c[2], 1, 4);
        }
}

__device__
#if INLINE == 0
__noinline__
#endif

void fp12_copy(fp12_t c, fp12_t a) {
 if(c == NULL){
  printf(" invalid c in fp12_copy \n");
 }
        fp6_copy(c[0], a[0]);
        fp6_copy(c[1], a[1]);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp12_frb(fp12_t c, fp12_t a, int i) {
        /* Cost of five multiplication in Fp^2 per Frobenius. */
        fp12_copy(c, a);
        for (; i % 12 > 0; i--) {
                fp6_frb(c[0], c[0], 1);
                fp2_frb(c[1][0], c[1][0], 1);
                fp2_frb(c[1][1], c[1][1], 1);
                fp2_frb(c[1][2], c[1][2], 1);
                fp2_mul_frb(c[1][0], c[1][0], 1, 1);
                fp2_mul_frb(c[1][1], c[1][1], 1, 3);
                fp2_mul_frb(c[1][2], c[1][2], 1, 5);
        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_dblm_low(fp2_t c, fp2_t a) {
        fp_dblm_low(c[0], a[0]);
        fp_dblm_low(c[1], a[1]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_sqr_unr(dv6_t c, fp6_t a) {
	dv2_t u0, u1, u2, u3, u4, u5;
	fp2_t t0, t1, t2, t3;

//	dv2_null(u0);
//	dv2_null(u1);
//	dv2_null(u2);
//	dv2_null(u3);
//	dv2_null(u4);
//	dv2_null(u5);
//	fp2_null(t0);
//	fp2_null(t1);
//	fp2_null(t2);
//	fp2_null(t3);

//	RLC_TRY {
		dv2_new(u0);
		dv2_new(u1);
		dv2_new(u2);
		dv2_new(u3);
		dv2_new(u4);
		dv2_new(u5);
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		fp2_new(t3);

		/* u0 = a_0^2 */
		fp2_sqrn_low(u0, a[0]);

		/* t1 = 2 * a_1 * a_2 */
		fp2_dblm_low(t0, a[1]);

#ifdef RLC_FP_ROOM
		fp2_mulc_low(u1, t0, a[2]);
#else
		fp2_muln_low(u1, t0, a[2]);
#endif

		/* u2 = a_2^2. */
		fp2_sqrn_low(u2, a[2]);

		/* t4 = a_0 + a_2. */
		fp2_addm_low(t3, a[0], a[2]);

		/* u3 = (a_0 + a_2 + a_1)^2. */
		fp2_addm_low(t2, t3, a[1]);
		fp2_sqrn_low(u3, t2);

		/* u4 = (a_0 + a_2 - a_1)^2. */
		fp2_subm_low(t1, t3, a[1]);
		fp2_sqrn_low(u4, t1);

		/* u4 = (u4 + u3)/2. */
#ifdef RLC_FP_ROOM
		fp2_addd_low(u4, u4, u3);
#else
		fp2_addc_low(u4, u4, u3);
#endif
		fp_hlvd_low(u4[0], u4[0]);
		fp_hlvd_low(u4[1], u4[1]);

		/* u3 = u3 - u4 - u1. */
#ifdef RLC_FP_ROOM
		fp2_addd_low(u5, u1, u4);
#else
		fp2_addc_low(u5, u1, u4);
#endif
		fp2_subc_low(u3, u3, u5);

		/* c2 = u4 - u0 - u2. */
#ifdef RLC_FP_ROOM
		fp2_addd_low(u5, u0, u2);
#else
		fp2_addc_low(u5, u0, u2);
#endif
		fp2_subc_low(c[2], u4, u5);

		/* c0 = u0 + u1 * E. */
		fp2_nord_low(u4, u1);
		fp2_addc_low(c[0], u0, u4);

		/* c1 = u3 + u2 * E. */
		fp2_nord_low(u4, u2);
		fp2_addc_low(c[1], u3, u4);
//	} RLC_CATCH_ANY {
//		RLC_THROW(ERR_CAUGHT);
//	} RLC_FINALLY {
		dv2_free(u0);
		dv2_free(u1);
		dv2_free(u2);
		dv2_free(u3);
		dv2_free(u4);
		dv2_free(u5);
		fp2_free(t0);
		fp2_free(t1);
		fp2_free(t2);
		fp2_free(t3);
//	}
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_sqr_lazyr(fp6_t c, fp6_t a) {
        dv6_t t;

//        dv6_null(t);

//        RLC_TRY {
                dv6_new(t);
                fp6_sqr_unr(t, a);
                fp2_rdcn_low(c[0], t[0]);
                fp2_rdcn_low(c[1], t[1]);
                fp2_rdcn_low(c[2], t[2]);
//        } RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        } RLC_FINALLY {
                dv6_free(t);
//        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_sqr(fp6_t c, fp6_t a) {
 fp6_sqr_lazyr(c,a);

}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_mul_nor(fp2_t c, fp2_t a){
 fp2_mul_nor_basic(c,a);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_mul_art(fp6_t c, fp6_t a) {
        fp2_t t0;

 //       fp2_null(t0);

 //       RLC_TRY {
                fp2_new(t0);

                /* (a_0 + a_1 * v + a_2 * v^2) * v = a_2 + a_0 * v + a_1 * v^2 */
                fp2_copy(t0, a[0]);
                fp2_mul_nor(c[0], a[2]);
                fp2_copy(c[2], a[1]);
                fp2_copy(c[1], t0);
//        } RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        } RLC_FINALLY {
                fp2_free(t0);
//        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_sub(fp6_t c, fp6_t a, fp6_t b) {
        fp2_sub(c[0], a[0], b[0]);
        fp2_sub(c[1], a[1], b[1]);
        fp2_sub(c[2], a[2], b[2]);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_inv(fp6_t c, fp6_t a) {
        fp2_t v0;
        fp2_t v1;
        fp2_t v2;
        fp2_t t0;

//        fp2_null(v0);
//        fp2_null(v1);
//        fp2_null(v2);
//        fp2_null(t0);

//        RLC_TRY {
                fp2_new(v0);
                fp2_new(v1);
                fp2_new(v2);
                fp2_new(t0);

                /* v0 = a_0^2 - E * a_1 * a_2. */
                fp2_sqr(t0, a[0]);
                fp2_mul(v0, a[1], a[2]);
                fp2_mul_nor(v2, v0);
                fp2_sub(v0, t0, v2);

                /* v1 = E * a_2^2 - a_0 * a_1. */
                fp2_sqr(t0, a[2]);
                fp2_mul_nor(v2, t0);
                fp2_mul(v1, a[0], a[1]);
                fp2_sub(v1, v2, v1);

                /* v2 = a_1^2 - a_0 * a_2. */
                fp2_sqr(t0, a[1]);
                fp2_mul(v2, a[0], a[2]);
                fp2_sub(v2, t0, v2);

                fp2_mul(t0, a[1], v2);
                fp2_mul_nor(c[1], t0);

                fp2_mul(c[0], a[0], v0);

                fp2_mul(t0, a[2], v1);
                fp2_mul_nor(c[2], t0);

                fp2_add(t0, c[0], c[1]);
                fp2_add(t0, t0, c[2]);
                fp2_inv(t0, t0);

                fp2_mul(c[0], v0, t0);
                fp2_mul(c[1], v1, t0);
                fp2_mul(c[2], v2, t0);
//        } RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        } RLC_FINALLY {
                fp2_free(v0);
                fp2_free(v1);
                fp2_free(v2);
                fp2_free(t0);
//        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_mul_lazyr(fp6_t c, fp6_t a, fp6_t b){
        dv6_t t;

//        dv6_null(t);

//        RLC_TRY {
                dv6_new(t);
                fp6_mul_unr(t, a, b);
                fp2_rdcn_low(c[0], t[0]);
                fp2_rdcn_low(c[1], t[1]);
                fp2_rdcn_low(c[2], t[2]);
//        } RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        } RLC_FINALLY {
                dv6_free(t);
//        }
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp6_mul(fp6_t c, fp6_t a, fp6_t b){
 fp6_mul_lazyr(c,a,b);
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp12_inv(fp12_t c, fp12_t a) {
        fp6_t t0;
        fp6_t t1;

//        fp6_null(t0);
//        fp6_null(t1);

//        RLC_TRY {
                fp6_new(t0);
                fp6_new(t1);

                fp6_sqr(t0, a[0]);
                fp6_sqr(t1, a[1]);
                fp6_mul_art(t1, t1);
                fp6_sub(t0, t0, t1);
                fp6_inv(t0, t0);

                fp6_mul(c[0], a[0], t0);
                fp6_neg(c[1], a[1]);
                fp6_mul(c[1], c[1], t0);
//        } RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        } RLC_FINALLY {
                fp6_free(t0);
                fp6_free(t1);
//        }
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp12_conv_cyc(fp12_t c, fp12_t a) {
        fp12_t t;

//        fp12_null(t);
//
//                fp12_new(t);

                /* First, compute c = a^(p^6 - 1). */
                /* t = a^{-1}. */
                fp12_inv(t, a);
                /* c = a^(p^6). */
                fp12_inv_cyc(c, a);
                /* c = a^(p^6 - 1). */
                fp12_mul(c, c, t);

                /* Second, compute c^(p^2 + 1). */
                /* t = c^(p^2). */
                fp12_frb(t, c, 2);

                /* c = c^(p^2 + 1). */
                fp12_mul(c, c, t);
                //fp12_free(t);
}


__device__
#if INLINE == 0
__noinline__
#endif
void fp2_norm_low(fp2_t c, fp2_t a) {
        fp2_t t;

        fp2_null(t);
//        RLC_TRY {
        fp2_new(t);
//#ifdef FP_QNRES
                /* If p = 3 mod 8, (1 + i) is a QNR/CNR. */
                fp_copy(t[0], a[1]);
                fp_add(c[1], a[0], a[1]);
                fp_sub(c[0], a[0], t[0]);
//#else
//                int qnr = fp2_field_get_qnr();
//                switch (fp_prime_get_mod8()) {
//                        case 3:
//                                /* If p = 3 mod 8, (1 + i) is a QNR/CNR. */
//                                fp_neg(t[0], a[1]);
//                                fp_add(c[1], a[0], a[1]);
//                                fp_add(c[0], t[0], a[0]);
//                                break;
//                        case 1:
//                        case 5:
//                                /* If p = 1,5 mod 8, (i) is a QNR/CNR. */
//                                fp2_mul_art(c, a);
//                                break;
//                        case 7:
//                                /* If p = 7 mod 8, we choose (2^k + i) as QNR/CNR. */
//                                fp2_mul_art(t, a);
//                                fp2_copy(c, a);
//                                while (qnr > 1) {
//                                        fp2_dbl(c, c);
//                                        qnr = qnr >> 1;
//                                }
//                                fp2_add(c, c, t);
//                                break;
//                }
//#endif
//        }
//        RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        }
//        RLC_FINALLY {
//                fp2_free(t);
//        }
}


__device__
#if INLINE == 0
__noinline__
#endif
void fp2_sqrm_low(fp2_t c, fp2_t a) {
        rlc_align dv2_t t;

        dv2_null(t);

//        RLC_TRY {
                dv2_new(t);
                fp2_sqrn_low(t, a);
                fp2_rdcn_low(c, t);
//        } RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        } RLC_FINALLY {
//                dv2_free(t);
//        }
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp12_sqr_pck_lazyr(fp12_t c, fp12_t a) {
	fp2_t t0, t1, t2;
	dv2_t u0, u1, u2, u3;

//	fp2_null(t0);
//	fp2_null(t1);
//	fp2_null(t2);
//	dv2_null(u0);
//	dv2_null(u1);
//	dv2_null(u2);
//	dv2_null(u3);
//
//	RLC_TRY {
//		fp2_new(t0);
//		fp2_new(t1);
//		fp2_new(t2);
//		dv2_new(u0);
//		dv2_new(u1);
//		dv2_new(u2);
//		dv2_new(u3);

		fp2_sqrn_low(u0, a[0][1]);
		fp2_sqrn_low(u1, a[1][2]);
		fp2_addm_low(t0, a[0][1], a[1][2]);
		fp2_sqrn_low(u2, t0);

		fp2_addc_low(u3, u0, u1);
		fp2_subc_low(u3, u2, u3);
		fp2_rdcn_low(t0, u3);

		fp2_addm_low(t1, a[1][0], a[0][2]);
		fp2_sqrm_low(t2, t1);
		fp2_sqrn_low(u2, a[1][0]);

		fp2_norm_low(t1, t0);
		fp2_addm_low(t0, t1, a[1][0]);
		fp2_dblm_low(t0, t0);
		fp2_addm_low(c[1][0], t0, t1);

		fp2_norh_low(u3, u1);
		fp2_sqrn_low(u1, a[0][2]);
		fp2_addc_low(u3, u0, u3);
		fp2_rdcn_low(t0, u3);
		fp2_subm_low(t1, t0, a[0][2]);
		fp2_dblm_low(t1, t1);
		fp2_addm_low(c[0][2], t1, t0);

		fp2_addc_low(u0, u2, u1);
		fp2_rdcn_low(t0, u0);
		fp2_subm_low(t0, t2, t0);
		fp2_addm_low(t1, t0, a[1][2]);
		fp2_dblm_low(t1, t1);
		fp2_addm_low(c[1][2], t0, t1);

		fp2_norh_low(u3, u1);
		fp2_addc_low(u3, u2, u3);
		fp2_rdcn_low(t0, u3);
		fp2_subm_low(t1, t0, a[0][1]);
		fp2_dblm_low(t1, t1);
		fp2_addm_low(c[0][1], t1, t0);
//		fp2_free(t0);
//		fp2_free(t1);
//		fp2_free(t2);
//		dv2_free(u0);
//		dv2_free(u1);
//		dv2_free(u2);
//		dv2_free(u3);
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_sqr_pck(fp12_t c, fp12_t a) {
fp12_sqr_pck_lazyr(c, a);

}
__device__
#if INLINE == 0
__noinline__
#endif
void fp2_inv_sim(fp2_t *c, fp2_t *a, int n) {
        int i;
        fp2_t u, *t = (fp2_t*) malloc(sizeof(fp2_t)*n);
//        fp2_t u, *t = RLC_ALLOCA(fp2_t, n);

        for (i = 0; i < n; i++) {
                fp2_null(t[i]);
        }
        fp2_null(u);

//        RLC_TRY {
                for (i = 0; i < n; i++) {
                        fp2_new(t[i]);
                }
                fp2_new(u);

                fp2_copy(c[0], a[0]);
                fp2_copy(t[0], a[0]);

                for (i = 1; i < n; i++) {
                        fp2_copy(t[i], a[i]);
                        fp2_mul(c[i], c[i - 1], t[i]);
                }

                fp2_inv(u, c[n - 1]);

                for (i = n - 1; i > 0; i--) {
                        fp2_mul(c[i], c[i - 1], u);
                        fp2_mul(u, u, t[i]);
                }
                fp2_copy(c[0], u);
//        }
//        RLC_CATCH_ANY {
//                RLC_THROW(ERR_CAUGHT);
//        }
//        RLC_FINALLY {
                for (i = 0; i < n; i++) {
                        fp2_free(t[i]);
                }
                fp2_free(u);
//                RLC_FREE(t);
        free(t);
//        }
}

__device__
#if INLINE == 0
__noinline__
#endif
void fp12_back_cyc_sim(fp12_t c[], fp12_t a[], int n) {
    fp2_t *t  =  (fp2_t*) malloc(sizeof(fp2_t)*n*3);
    fp2_t
        *t0 = t + 0 * n,
        *t1 = t + 1 * n,
        *t2 = t + 2 * n;

	if (n == 0) {
		free(t);
		return;
	}

	//RLC_TRY {
		if (t == NULL) {
                   printf(" No memory in fp12_back_cyc_sim \n");
		}
		for (int i = 0; i < n; i++) {
			fp2_null(t0[i]);
			fp2_null(t1[i]);
			fp2_null(t2[i]);
			fp2_new(t0[i]);
			fp2_new(t1[i]);
			fp2_new(t2[i]);
		}

		for (int i = 0; i < n; i++) {
			/* t0 = g4^2. */
			fp2_sqr(t0[i], a[i][0][1]);
			/* t1 = 3 * g4^2 - 2 * g3. */
			fp2_sub(t1[i], t0[i], a[i][0][2]);
			fp2_dbl(t1[i], t1[i]);
			fp2_add(t1[i], t1[i], t0[i]);
			/* t0 = E * g5^2 + t1. */
			fp2_sqr(t2[i], a[i][1][2]);
			fp2_mul_nor(t0[i], t2[i]);
			fp2_add(t0[i], t0[i], t1[i]);
			/* t1 = (4 * g2). */
			fp2_dbl(t1[i], a[i][1][0]);
			fp2_dbl(t1[i], t1[i]);
		}

		/* t1 = 1 / t1. */
		fp2_inv_sim(t1, t1, n);

		for (int i = 0; i < n; i++) {
			/* t0 = g1. */
			fp2_mul(c[i][1][1], t0[i], t1[i]);

			/* t1 = g3 * g4. */
			fp2_mul(t1[i], a[i][0][2], a[i][0][1]);
			/* t2 = 2 * g1^2 - 3 * g3 * g4. */
			fp2_sqr(t2[i], c[i][1][1]);
			fp2_sub(t2[i], t2[i], t1[i]);
			fp2_dbl(t2[i], t2[i]);
			fp2_sub(t2[i], t2[i], t1[i]);
			/* t1 = g2 * g5. */
			fp2_mul(t1[i], a[i][1][0], a[i][1][2]);
			/* t2 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
			fp2_add(t2[i], t2[i], t1[i]);
			fp2_mul_nor(c[i][0][0], t2[i]);
			fp_add_dig(c[i][0][0][0], c[i][0][0][0], 1);

			fp2_copy(c[i][0][1], a[i][0][1]);
			fp2_copy(c[i][0][2], a[i][0][2]);
			fp2_copy(c[i][1][0], a[i][1][0]);
			fp2_copy(c[i][1][2], a[i][1][2]);
		}
//	} RLC_CATCH_ANY {
//		RLC_THROW(ERR_CAUGHT);
//	} RLC_FINALLY {
//		for (int i = 0; i < n; i++) {
//			fp2_free(t0[i]);
//			fp2_free(t1[i]);
//			fp2_free(t2[i]);
//		}
//		RLC_FREE(t);
//	}
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_exp_cyc_sps(fp12_t c, fp12_t a, const int *b, int len, int sign) {
	int i, j, k, w = len;
        fp12_t t;
        fp12_t u[6];

	if (len == 0) {
//		RLC_FREE(u);
		fp12_set_dig(c, 1);
		return;
	}

//	fp12_null(t);

//	RLC_TRY {
		if (u == NULL) {
                 printf(" no memory in fp12_exp_cyc_sps...\n");
		}
		for (i = 0; i < w; i++) {
//			fp12_null(u[i]);
//			fp12_new(u[i]);

  u[i][0][0][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  u[i][0][0][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  u[i][0][1][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  u[i][0][1][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  u[i][0][2][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  u[i][0][2][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  u[i][1][0][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  u[i][1][0][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  u[i][1][1][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  u[i][1][1][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  u[i][1][2][0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  u[i][1][2][1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
		}
		fp12_new(t);

		fp12_copy(t, a);
		if (b[0] == 0) {
			for (j = 0, i = 1; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp12_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp12_inv_cyc(u[i - 1], t);
				} else {
					fp12_copy(u[i - 1], t);
				}
			}

			fp12_back_cyc_sim(u, u, w - 1);

			fp12_copy(c, a);
			for (i = 0; i < w - 1; i++) {
				fp12_mul(c, c, u[i]);
			}
		} else {
			for (j = 0, i = 0; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
 printf("i: %d \n",i);
				for (; j < k; j++) {
					fp12_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp12_inv_cyc(u[i], t);
				} else {
					fp12_copy(u[i], t);
				}
			}

			fp12_back_cyc_sim(u, u, w);

			fp12_copy(c, u[0]);
			for (i = 1; i < w; i++) {
				fp12_mul(c, c, u[i]);
			}
		}

		if (sign == RLC_NEG) {
			fp12_inv_cyc(c, c);
		}
//	}
//	RLC_CATCH_ANY {
//		RLC_THROW(ERR_CAUGHT);
//	}
//	RLC_FINALLY {
//		for (i = 0; i < w; i++) {
//			fp12_free(u[i]);
//		}
//		fp12_free(t);
//		RLC_FREE(u);
//	}
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_sqr_cyc_lazyr(fp12_t c, fp12_t a) {
	fp2_t t0, t1, t2;
	dv2_t u0, u1, u2, u3;

//	fp2_null(t0);
//	fp2_null(t1);
//	fp2_null(t2);
//	dv2_null(u0);
//	dv2_null(u1);
//	dv2_null(u2);
//	dv2_null(u3);

//	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		dv2_new(u0);
		dv2_new(u1);
		dv2_new(u2);
		dv2_new(u3);

		fp2_sqrn_low(u2, a[0][0]);
		fp2_sqrn_low(u3, a[1][1]);
		fp2_addm_low(t1, a[0][0], a[1][1]);

		fp2_norh_low(u0, u3);
		fp2_addc_low(u0, u0, u2);
		fp2_rdcn_low(t0, u0);

		fp2_sqrn_low(u1, t1);
		fp2_addc_low(u2, u2, u3);
		fp2_subc_low(u1, u1, u2);
		fp2_rdcn_low(t1, u1);

		fp2_subm_low(c[0][0], t0, a[0][0]);
		fp2_addm_low(c[0][0], c[0][0], c[0][0]);
		fp2_addm_low(c[0][0], t0, c[0][0]);

		fp2_addm_low(c[1][1], t1, a[1][1]);
		fp2_addm_low(c[1][1], c[1][1], c[1][1]);
		fp2_addm_low(c[1][1], t1, c[1][1]);

		fp2_sqrn_low(u0, a[0][1]);
		fp2_sqrn_low(u1, a[1][2]);
		fp2_addm_low(t0, a[0][1], a[1][2]);
		fp2_sqrn_low(u2, t0);

		fp2_addc_low(u3, u0, u1);
		fp2_subc_low(u3, u2, u3);
		fp2_rdcn_low(t0, u3);

		fp2_addm_low(t1, a[1][0], a[0][2]);
		fp2_sqrm_low(t2, t1);
		fp2_sqrn_low(u2, a[1][0]);

		fp2_norm_low(t1, t0);
		fp2_addm_low(t0, t1, a[1][0]);
		fp2_addm_low(t0, t0, t0);
		fp2_addm_low(c[1][0], t0, t1);

		fp2_norh_low(u3, u1);
		fp2_addc_low(u3, u0, u3);
		fp2_rdcn_low(t0, u3);
		fp2_subm_low(t1, t0, a[0][2]);

		fp2_sqrn_low(u1, a[0][2]);

		fp2_addm_low(t1, t1, t1);
		fp2_addm_low(c[0][2], t1, t0);

		fp2_norh_low(u3, u1);
		fp2_addc_low(u3, u2, u3);
		fp2_rdcn_low(t0, u3);
		fp2_subm_low(t1, t0, a[0][1]);
		fp2_addm_low(t1, t1, t1);
		fp2_addm_low(c[0][1], t1, t0);

		fp2_addc_low(u0, u2, u1);
		fp2_rdcn_low(t0, u0);
		fp2_subm_low(t0, t2, t0);
		fp2_addm_low(t1, t0, a[1][2]);
		fp2_dblm_low(t1, t1);
		fp2_addm_low(c[1][2], t0, t1);
//	} RLC_CATCH_ANY {
//		RLC_THROW(ERR_CAUGHT);
//	} RLC_FINALLY {
		fp2_free(t0);
		fp2_free(t1);
		fp2_free(t2);
		dv2_free(u0);
		dv2_free(u1);
		dv2_free(u2);
		dv2_free(u3);
//	}
}
__device__
#if INLINE == 0
__noinline__
#endif
void fp12_sqr_cyc(fp12_t c, fp12_t a){
 fp12_sqr_cyc_lazyr(c,a);
}
__device__
#if INLINE == 0
__noinline__
#endif
static void pp_exp_b12(fp12_t c, fp12_t a) {
	fp12_t t0, t1, t2, t3;
	bn_t x;
	int *b;
	int l;

//	fp12_null(t0);
//	fp12_null(t1);
//	fp12_null(t2);
//	fp12_null(t3);
//	bn_null(x);
//
 printf(" Final exponentiation...\n");
		fp12_new(t0);
		fp12_new(t1);
		fp12_new(t2);
		fp12_new(t3);
//		bn_new(x);

		/*
		 * Final exponentiation following Ghammam and Fouotsa:
		 * On the Computation of Optimal Ate Pairing at the 192-bit Level.
		 */
//		fp_prime_get_par(x);

  x = (bn_t ) malloc(sizeof(bn_st));
  x->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
  x->alloc = RLC_BN_SIZE;
  x->used = 4;
  x->sign = RLC_POS;
  x->dp[0] = 1;

//		b = fp_prime_get_par_sps(&l);
                l = 6;
                b = (int*)malloc(sizeof(int)*(RLC_TERMS + 1));
                b[0] = 16;
                b[1] = 48;
                b[2] = 57;
                b[3] = 60;
                b[4] = -62;
                b[5] = 64;
                b[6] = 0;
                b[7] = 0;
                b[8] = 0;
                b[9] = 0;
                b[10] = 0;
                b[11] = 0;
                b[12] = 0;
                b[13] = 0;
                b[14] = 0;
                b[15] = 0;
                b[16] = 0;

		/* First, compute m^(p^6 - 1)(p^2 + 1). */
		fp12_conv_cyc(c, a);

		/* Now compute m^((p^4 - p^2 + 1) / r). */
		/* t0 = f^2. */
		fp12_sqr_cyc(t0, c);

		/* t1 = f^x. */
		fp12_exp_cyc_sps(t1, c, b, l, bn_sign(x));

		/* t2 = f^(x^2). */
		fp12_exp_cyc_sps(t2, t1, b, l, bn_sign(x));

		/* t1 = t2/(t1^2 * f). */
		fp12_inv_cyc(t3, c);
		fp12_sqr_cyc(t1, t1);
		fp12_mul(t1, t1, t3);
		fp12_inv_cyc(t1, t1);
		fp12_mul(t1, t1, t2);

		/* t2 = t1^x. */
		fp12_exp_cyc_sps(t2, t1, b, l, bn_sign(x));

		/* t3 = t2^x/t1. */
		fp12_exp_cyc_sps(t3, t2, b, l, bn_sign(x));
		fp12_inv_cyc(t1, t1);
		fp12_mul(t3, t1, t3);

		/* t1 = t1^(-p^3 ) * t2^(p^2). */
		fp12_inv_cyc(t1, t1);
		fp12_frb(t1, t1, 3);
		fp12_frb(t2, t2, 2);
		fp12_mul(t1, t1, t2);

		/* t2 = f * f^2 * t3^x. */
		fp12_exp_cyc_sps(t2, t3, b, l, bn_sign(x));
                free(b);
		fp12_mul(t2, t2, t0);
		fp12_mul(t2, t2, c);

		/* Compute t1 * t2 * t3^p. */
		fp12_mul(t1, t1, t2);
		fp12_frb(t2, t3, 1);
		fp12_mul(c, t1, t2);
 printf(" Leaving the final exponentiation step...\n");

//		fp12_free(t0);

//		fp12_free(t1);
//		fp12_free(t2);
//		fp12_free(t3);
//		bn_free(x);
}
__device__
#if INLINE == 0
__noinline__
#endif
static void pp_exp_k12(fp12_t c, fp12_t a) {
pp_exp_b12(c, a);
}
__device__
#if INLINE == 0
__noinline__
#endif
void pp_map_sim_oatep_k12(fp12_t r, ep_t *p, ep2_t *q, int m) {
 int i, j;

 ep_t  *_p = (ep_t*) malloc((m) * sizeof(ep_t));
 ep2_t *t  = (ep2_t*) malloc((m) * sizeof(ep2_t));
 ep2_t *_q = (ep2_t*) malloc((m) * sizeof(ep2_t));

 bn_t a;

 printf(" Calculating pairing...\n");
 if (_p == NULL || _q == NULL || t == NULL) {
  printf(" No memory in pp_map_sim_oatep_k12...\n");
 }

  a = (bn_t ) malloc(sizeof(bn_st));
  a->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
  a->alloc = RLC_BN_SIZE;
  a->used = 1;
  a->sign = RLC_NEG;
  a->dp[0] = 15132376222941642752;
  bn_print(a);

 printf(" pointer init...\n");
//  for (i = 0; i < m; i++) {
//   ep_new(_p[i]);
//   ep2_new(_q[i]);
//   ep2_new(t[i]);
//  }

  _q[0] = (ep2_t)malloc(sizeof(ep2_st));
  _q[0]->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  _q[0]->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  _q[0]->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  _q[0]->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  _q[0]->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  _q[0]->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  _q[1] = (ep2_t)malloc(sizeof(ep2_st));
  _q[1]->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  _q[1]->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  _q[1]->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  _q[1]->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  _q[1]->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  _q[1]->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t[0] = (ep2_t)malloc(sizeof(ep2_st));
  t[0]->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t[0]->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t[0]->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t[0]->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t[0]->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t[0]->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t[1] = (ep2_t)malloc(sizeof(ep2_st));
  t[1]->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t[1]->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t[1]->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t[1]->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  t[1]->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  t[1]->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

 _p[0] = (ep_t)malloc(sizeof(ep_st));
 _p[1] = (ep_t)malloc(sizeof(ep_st));

 printf(" normalisation...\n");
 printf(" q: \n");
  j = 0;
  for (i = 0; i < m; i++) {
   if (!ep_is_infty(p[i]) && !ep2_is_infty(q[i])) {
    printf("i/p: %d \n",i);
    ep_print(p[i]);
    ep_norm(_p[j], p[i]);
    printf("i/q: %d \n",i);
    ep2_print(q[i]);
    ep2_norm(_q[j++], q[i]);
   }
  }

  fp12_set_dig(r, 1);
  printf(" Miller loop...\n");
  /* r = f_{|a|,Q}(P). */
  clock_t start = clock(); 
  pp_mil_k12(r, t, _q, _p, j, a);
  clock_t stop = clock();
  printf("pp_mil_k12 took: %d cycles \n",(int)(stop - start));

  free(_q[0]->x[0]);
  free(_q[0]->x[1]);

  free(_q[0]->y[0]);
  free(_q[0]->y[1]);

  free(_q[0]->z[0]);
  free(_q[0]->z[1]);

  free(_q[1]->x[0]);
  free(_q[1]->x[1]);

  free(_q[1]->y[0]);
  free(_q[1]->y[1]);

  free(_q[1]->z[0]);
  free(_q[1]->z[1]);
  free(_q[0]);
  free(_q[1]);

  free(t[0]->x[0]);
  free(t[0]->x[1]);

  free(t[0]->y[0]);
  free(t[0]->y[1]);

  free(t[0]->z[0]);
  free(t[0]->z[1]);

  free(t[1]->x[0]);
  free(t[1]->x[1]);

  free(t[1]->y[0]);
  free(t[1]->y[1]);

  free(t[1]->z[0]);
  free(t[1]->z[1]);

  free(t[1]);
  free(t[0]);

 free(_p[0]);
 free(_p[1]);

  if (bn_sign(a) == RLC_NEG) {
   fp12_inv_cyc(r, r);
  }
  start = clock(); 
  pp_exp_k12(r, r);
  stop = clock();
  printf("pp_exp_k12 took: %d cycles \n",(int)(stop - start));
 printf(" Result: \n");
 fp12_print(r);

  free(p);
  free(q);
  free(_p);
  free(_q);
  free(t);
  free(a->dp);
  free(a);
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
__device__
#if INLINE == 0
__noinline__
#endif
void mapmessage(uint8_t *prime, uint64_t *prime2, char* message_string_1)
{
 bn_t e, e2;
   uint8_t  idx0;
   uint8_t  idx1;
   time_t t;
   ep2_t p,qqq;
   ep2_t q;
   bn_t x;

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

// vector<uint8_t> message = {11};

// 15CC3F292D66704A 62687D6E2DCB5913 7C9E20D357539F96 9F51EABD020D64E0 81792D01F15CC248 1D44777B8BAFC9FD ttt[0]
// 147765C676F3B800 6798BA4300F29F76 27CBE052A3D0397E CE0A4A7079E5EFEF 45DECCC08A4147E2 345BA7EC94B37852 ttt[1]
// P+Q after Forbenius: 
// 19C38BACB92FE1AB DB60CB93953905D4 6074A7272E38D5B1 1BE58CE84F66949E 7C892A9D9BA26B3B 6E5762510852B323
// 0FF88E19FF154346 5E0BAFA097B616B8 0A81717E5A597AF5 71F023E723E3CB89 A9C63F913BEB0FD1 E33027CA5649D4F3
// 055ABA66857688CB F9027B0E501079C8 6F7A0A85671FA86F D053D9F741A56F0D F50B5BDF4AE80DA5 9B9E873BE7CFE6A0
// 1979ECA2D88265FB 96CF461427634369 7074995C4D3FA986 CEA781C98A77AAB4 F9F914F079C5C5D4 FCAC03952C4937EF
// 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000001
// 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000

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
// for(int i = 0; i<256; i++){
//  printf("%02x",msg[i]);
// }


  p = (ep2_t)malloc(sizeof(ep2_st));
  p->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  p->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  p->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  p->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  q = (ep2_t)malloc(sizeof(ep2_st));
  q->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  q->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  q->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  q->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  q->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  q->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  bn_read_bin(e, msg, 64);
  bn_read_bin(e2, msg+64, 64);
  signmessage(e,e2, 1,p);

  bn_read_bin(e, msg+128, 64);
  bn_read_bin(e2, msg+192, 64);
  signmessage(e,e2, 1,q);
  return;

  ep2_add_projc(p, p, q);
  printf("P+Q: \n");
  ep2_print(p);
  ep2_norm(p, p);
  printf("P+Q after normalization: \n");
  ep2_print(p);
  ep2_mul_cof_b12(p, p);
  printf("P+Q after Forbenius: \n");
  ep2_print(p);

// Ez lesz a titkos kulcs
  x = (bn_t ) malloc(sizeof(bn_st));
  x->dp = (dig_t* ) malloc(RLC_BN_SIZE * sizeof(dig_t));
  x->alloc = RLC_BN_SIZE;
  x->used = 4;
  x->sign = RLC_POS;

 char privatekey[65] = "377091F0E728463BC2DA7D546C53B9F6B81DF4A1CC1AB5BF29C5908B7151A32D";
 const char privatekey0[17] = "29C5908B7151A32D";
 const char privatekey1[17] = "B81DF4A1CC1AB5BF";
 const char privatekey2[17] = "C2DA7D546C53B9F6";
 const char privatekey3[17] = "377091F0E728463B";

 x->dp[0] = xtou64(privatekey0);
 x->dp[1] = xtou64(privatekey1);
 x->dp[2] = xtou64(privatekey2);
 x->dp[3] = xtou64(privatekey3);
  
 printf("Private key: \n");
  bn_print(x);
// A BLS aláírás a lehashelt üzenet, amiből pont lesz x a titkos kulcs 
  ep2_mul_basic(p,p,x);
  printf("Signature: \n");
  ep2_print(p);
// Itt ki kell számolni a publikus kulcsot a titkos kulcsból
// A publikus kulcs a privát kulcs x a generátor
  ep_st* pp;
  pp = (ep_st*) malloc(sizeof(ep_st));

  ep_mul_gen(pp, x);
  printf("Public key: \n");
  ep_print(pp);

  free(pp);
  ep_t *ppp; 
  ep2_t *qq;

  fp12_t rrr;
  fp12_new(rrr);

  int m = 2;
  ppp = (ep_t*) malloc((m) * sizeof(ep_t));
  qq = (ep2_t*) malloc((m) * sizeof(ep2_t));

  for (int i = 0; i < m; i++) {
   ep_new(ppp[i]);
//   ep2_new(qq[i]);
  }

  ppp[0] = (ep_t)malloc(sizeof(ep_st));
  ppp[1] = (ep_t)malloc(sizeof(ep_st));


  qq[0] = (ep2_t)malloc(sizeof(ep2_st));
  qq[0]->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  qq[0]->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  qq[0]->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  qq[0]->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  qq[0]->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  qq[0]->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  qq[1] = (ep2_t)malloc(sizeof(ep2_st));
  qq[1]->x[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  qq[1]->x[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  qq[1]->y[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  qq[1]->y[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  qq[1]->z[0] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));
  qq[1]->z[1] = (fp_t)malloc((RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)) * sizeof(dig_t));

  ep2_copy(qq[1],p);
  pp_map_sim_oatep_k12(rrr, ppp, qq, m);


// És a publikus kulccsal, az üzenettel és az aláírással lehet hitelesíteni
// Itt a hash-elést nem kell még egyszer elvégezni, mert a pont már megvan

////////////////////////////////////////////////////////////

  free(p);
  free(x->dp);
  free(x);


  free(msg);
  free(e->dp);
  free(e2->dp);

  free(e);
  free(e2);
  return;
}
__global__
void runbls(uint8_t *prime, uint64_t *prime2, char* message_string_1, int size)
{

  for(int i=0; i < size; i++){
   if(threadIdx.x == i){
    mapmessage(prime,prime2,message_string_1 + i * 512);
   }
  }
  return;
}
int mpc(){

   cudaDeviceProp prop;

      cudaGetDeviceProperties(&prop, 0);

      printf(" Name: %s\n",prop.name );
      printf(" Compute capability: %d.%d\n", prop.major, prop.minor );
      printf(" Clock rate: %d\n",prop.clockRate );
      printf(" SM count:  %d\n",prop.multiProcessorCount );
      printf(" Max blocks per SM:  %d\n",prop.maxBlocksPerMultiProcessor );
      printf(" Max threads per SM:  %d\n",prop.maxThreadsPerMultiProcessor );
      printf(" Total global memory: %ld (%d MB)\n", prop.totalGlobalMem, int(prop.totalGlobalMem*9.5367e-7));
      printf(" Multiprocessor count: %d\n", prop.multiProcessorCount);
      return prop.multiProcessorCount;
}
int main(int argc, char *argv[])
{
  uint8_t *msg, *d_msg;
  uint64_t *msg2, *d_msg2;
  uint8_t *msg_first, *d_msg_first;

  uint8_t *prime, *cuda_prime;
  uint64_t *prime_2, *cuda_prime_2;

  uint64_t *quotient, *remainder;

  int info =  mpc();
  int parallel;

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

//  char message_string_1[5130] = "c70dbacf6414ea05360d6473c0a1e642b9eceeb49a5bab0d59c44864581dac4643303634876cc3f878fbb5fc334dc072a7fce16c5bdd91b70ff3aca4c178ecd57804bb38093ca6df3a34ee1b8001acab17fcb9df58e4630c9201687491cfd39f2e9600ba610a72d7b6cf731bbce9f4320a3ef506a5a574474331bab6fc45b3798aea69f8be5513ae3e69b073ecf82b2a5e63decb15ff32c2146374868189359bfc6ae1cfa585b7810304ac30aa28f2654e05a422148f1f5884657b9d02dc0ce1787e53abe2d0ea79f140bc95cb2564e27fd60399e3cbdac7fb7e3e1bd166033ac375ea14c80cdadddefbeebf263f42b154ba0228a9163f5be49242a96b30ce66";
  char* message_string_1;
  sscanf (argv[1],"%d",&parallel);
  
  printf("running on (%d) threads \n",parallel);
  message_string_1 = (char*) malloc(parallel*513*sizeof(char));

  for(int ii=0; ii < parallel*513; ii++){
   message_string_1[ii] = 'c';
  }

  char* dmsg_to_transfer;
  cudaMalloc(&dmsg_to_transfer, parallel*513*sizeof(char)); 

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
  cudaMemcpy(dmsg_to_transfer, message_string_1, parallel*513*sizeof(char), cudaMemcpyHostToDevice);

  size_t deviceLimit;
  gpuErrChk(cudaDeviceGetLimit(&deviceLimit, cudaLimitStackSize));
//  printf("Original Device stack size: %d\n", (int) deviceLimit);
    
  cudaDeviceSetLimit(cudaLimitMallocHeapSize, 256*1024*1024);
  gpuErrChk(cudaDeviceSetLimit(cudaLimitStackSize, 80*1024));
  gpuErrChk(cudaDeviceGetLimit(&deviceLimit, cudaLimitStackSize));

  cudaEvent_t start, stop;
  float elapsedTime;

  cudaEventCreate(&start);
  cudaEventRecord(start,0);

  runbls<<<1, parallel>>>(cuda_prime, cuda_prime_2, dmsg_to_transfer, parallel);


  cudaEventCreate(&stop);
  cudaEventRecord(stop,0);
  cudaEventSynchronize(stop);

  cudaEventElapsedTime(&elapsedTime, start,stop);
  printf("Elapsed time : %f ms\n" ,elapsedTime);
  printf("Unit time : %f ms\n" ,elapsedTime/(parallel*NTHREADS));

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
