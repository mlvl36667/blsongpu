/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of hashing to a prime elliptic curve over a quadratic
 * extension.
 *
 * @ingroup epx
 */

#include <inttypes.h>

#include "relic_core.h"
#include "relic_md.h"
#include "relic_tmpl_map.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#ifdef EP_CTMAP
/**
 * Evaluate a polynomial represented by its coefficients using Horner's rule.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the input value.
 * @param[in] coeffs		- the vector of coefficients in the polynomial.
 * @param[in] len			- the degree of the polynomial.
 */
TMPL_MAP_HORNER(fp2, fp2_t)

/**
 * Generic isogeny map evaluation for use with SSWU map.
 */
TMPL_MAP_ISOGENY_MAP(ep2, fp2, iso2)
#endif /* EP_CTMAP */

/**
 * Simplified SWU mapping.
 */
#define EP2_MAP_COPY_COND(O, I, C)                                                       \
	do {                                                                                 \
		dv_copy_cond(O[0], I[0], RLC_FP_DIGS, C);                                        \
		dv_copy_cond(O[1], I[1], RLC_FP_DIGS, C);                                        \
	} while (0)
TMPL_MAP_SSWU(ep2, fp2, fp_t, EP2_MAP_COPY_COND)

/**
 * Shallue--van de Woestijne map.
 */
TMPL_MAP_SVDW(ep2, fp2, fp_t, EP2_MAP_COPY_COND)
#undef EP2_MAP_COPY_COND

/* caution: this function overwrites k, which it uses as an auxiliary variable */
static inline int fp2_sgn0(const fp2_t t, bn_t k) {
	const int t_0_zero = fp_is_zero(t[0]);

	fp_prime_back(k, t[0]);
	const int t_0_neg = bn_get_bit(k, 0);

	fp_prime_back(k, t[1]);
	const int t_1_neg = bn_get_bit(k, 0);

	/* t[0] == 0 ? sgn0(t[1]) : sgn0(t[0]) */
	return t_0_neg | (t_0_zero & t_1_neg);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep2_map_from_field(ep2_t p, const uint8_t *uniform_bytes, int len) {
        bn_t k;
        bn_t k2;
        bn_t k3;
        bn_t k4;
/* ------------------  */
        bn_t b1,b2,b3;
        bn_t x1,x2,x3;
        bn_t r1,r2,r3;
        bn_t r4,r5,r6;
        bn_t r7,r8,r9;
        bn_t d1,d2,d3;
        bn_t s1,s2,s3;
        bn_t sm1,sm2,sm3;
/* ------------------  */
        fp2_t t;
        ep2_t q;
        int neg;
        /* enough space for two extension field elements plus extra bytes for uniformity */
        const int len_per_elm = (FP_PRIME + ep_param_level() + 7) / 8;

        bn_null(k);
        bn_null(k2);
        fp2_null(t);
        ep2_null(q);

        RLC_TRY {
                if (len != 2* len_per_elm) {
                  RLC_THROW(ERR_NO_VALID);
                }

                bn_new(k);
                bn_new(k2);
                fp2_new(t);
                ep2_new(q);

                /* which hash function should we use? */
                const int abNeq0 = (ep2_curve_opt_a() != RLC_ZERO) && (ep2_curve_opt_b() != RLC_ZERO);
                void (*const map_fn)(ep2_t, fp2_t) = (ep2_curve_is_ctmap() || abNeq0) ? ep2_map_sswu : ep2_map_svdw;

#define EP2_MAP_CONVERT_BYTES(IDX)                                                               \
        do {                                                                                     \
                bn_read_bin(k, uniform_bytes + 2 * IDX * len_per_elm, len_per_elm);              \
                printf("\n k: \n");                                                     \
                bn_print(k);                                                                     \
                fp_prime_conv(t[0], k);                                                          \
                bn_read_bin(k, uniform_bytes + (2 * IDX + 1) * len_per_elm, len_per_elm);  \
                printf("\n k: \n");                                                     \
                bn_print(k);                                                                     \
                fp_prime_conv(t[1], k);                                                          \
        } while (0)

#define EP2_MAP_APPLY_MAP(PT)                                                            \
        do {                                                                                 \
                /* sign of t */                                                                  \
                neg = fp2_sgn0(t, k);                                                            \
                /* convert */                                                                    \
                map_fn(PT, t);                                                                   \
                /* compare sign of y to sign of t; fix if necessary */                           \
                neg = neg != fp2_sgn0(PT->y, k);                                                 \
                fp2_neg(t, PT->y);                                                               \
                dv_copy_cond(PT->y[0], t[0], RLC_FP_DIGS, neg);                                  \
                dv_copy_cond(PT->y[1], t[1], RLC_FP_DIGS, neg);                                  \
        } while (0)

                /* first map invocation */
                EP2_MAP_CONVERT_BYTES(0);
                printf("\n 1. message: \n");
                fp2_print(t);
                EP2_MAP_APPLY_MAP(p);
                TMPL_MAP_CALL_ISOMAP(ep2, p);

//                printf("p: \n");
//                ep2_print(p);
                
                /* second map invocation */
                EP2_MAP_CONVERT_BYTES(1);
                printf("\n 2. message: \n");
                fp2_print(t);
                EP2_MAP_APPLY_MAP(q);
                TMPL_MAP_CALL_ISOMAP(ep2, q);
//                printf("q: \n");
//                ep2_print(q);

                /* XXX(rsw) could add p and q and then apply isomap,
                 * but need ep_add to support addition on isogeny curves */

#undef EP2_MAP_CONVERT_BYTES
#undef EP2_MAP_APPLY_MAP

                /* sum the result */
                ep2_add(p, p, q);
//                printf("1. P+Q: \n");
//                ep2_print(p);
                ep2_norm(p, p);
//                printf("2. P+Q: \n");
//                ep2_print(p);
                ep2_mul_cof(p, p);
//                printf("3. P+Q: \n");
//                ep2_print(p);
 printf(" ------------------------------------ \n");
                bn_null(k3);
                bn_new(k3);

                bn_null(b1);
                bn_new(b1);
                bn_null(b2);
                bn_new(b2);
                bn_null(b3);
                bn_new(b3);

                bn_set_dig(b1,33);                                                                    
                bn_set_dig(b2,32);                                                                    
                bn_set_dig(b3,31);                                                                    

                bn_null(x1);
                bn_new(x1);
                bn_null(x2);
                bn_new(x2);
                bn_null(x3);
                bn_new(x3);

                bn_null(s1);
                bn_new(s1);
                bn_null(s2);
                bn_new(s2);
                bn_null(s3);
                bn_new(s3);
                bn_mul(s1,b2,b3);
                bn_mul(s2,b1,b3);
                bn_mul(s3,b2,b1);

                bn_null(sm1);
                bn_new(sm1);
                bn_null(sm2);
                bn_new(sm2);
                bn_null(sm3);
                bn_new(sm3);
                bn_set_dig(sm1,17);                                                                    
                bn_set_dig(sm2,31);                                                                    
                bn_set_dig(sm3,16);                                                                    
                
// 2^{65}-1 = 18446744073709551615
                bn_set_dig(k2,18446744073709551615);                                                                    
                printf("\n k2: \n");
                bn_print(k2);                                                                    
                bn_set_dig(k3,1);                                                                    
                bn_add(r1,k2,k3);
                printf("\n r1: \n");
                bn_print(r1);                                                                    
                bn_div_rem(d1,r1,k2,b1);
                bn_div_rem(d2,r2,k2,b2);
                bn_div_rem(d3,r3,k2,b3);

                printf("\n r1: \n");
                bn_print(r1);                                                                    
                printf("\n r2: \n");
                bn_print(r2);                                                                    
                printf("\n r3: \n");
                bn_print(r3);                                                                    

                bn_set_dig(k3,1);                                                                    
                bn_div_rem(d1,r4,k3,b1);
                bn_div_rem(d2,r5,k3,b2);
                bn_div_rem(d3,r6,k3,b3);

                printf("\n r4: \n");
                bn_print(r4);                                                                    
                printf("\n r5: \n");
                bn_print(r5);                                                                    
                printf("\n r6: \n");
                bn_print(r6);                                                                    
// operation in basis p_1
                bn_add(r7,r1,r4);
                printf("\n r7: \n");
                bn_print(r7);                                                                    
                bn_copy(r4,r7);                                                                    
//                bn_div_rem(d1,r4,r7,b1);
// operation in basis p_2
                bn_add(r8,r2,r5);
                printf("\n r8: \n");
                bn_print(r8);                                                                    
                bn_copy(r5,r8);                                                                    
//                bn_div_rem(d1,r5,r8,b2);
// operation in basis p_3
                bn_add(r9,r3,r6);
                printf("\n r9: \n");
                bn_print(r9);                                                                    
                bn_copy(r6,r9);                                                                    
//                bn_div_rem(d1,r6,r9,b3);

                bn_mul(r7,sm1,r4);
                printf("\n r7: \n");
                bn_print(r7);                                                                    
                bn_div_rem(d1,r4,r7,b1);
                printf("\n r4: \n");
                bn_print(r4);                                                                    
                bn_mul(r8,sm2,r5);
                bn_div_rem(d1,r5,r8,b2);
                bn_mul(r9,sm3,r6);
                bn_div_rem(d1,r6,r9,b3);

                bn_mul(r7,s1,r4);
                printf("\n r7: \n");
                bn_print(r7);                                                                    
                bn_mul(r8,s2,r5);
                bn_mul(r9,s3,r6);

                bn_add(r1,r7,r8);
                bn_add(r2,r1,r9);
                printf("\n r2: \n");
                bn_print(r2);                                                                    

                bn_mul(s1,b2,b1);
                bn_mul(s2,s1,b3);
                printf("\n s2: \n");
                bn_print(s2);                                                                    

                bn_div_rem(d1,r1,r2,s2);
                printf("\n result: \n");
                bn_print(r1);                                                                    
                                
//                bn_add_rns();

//void bn_div_rem(bn_t c, bn_t d, const bn_t a, const bn_t b) {

                printf(" %d \n",k2->dp[0]);

                bn_null(k4);
                bn_new(k4);
                bn_div(k4,k2,k3);
                printf("\n k4: \n");
                bn_print(k4);                                                                    
//bn_div(bn_t c, const bn_t a, const bn_t b)
 printf(" ------------------------------------ \n");
        }
        RLC_CATCH_ANY {
                RLC_THROW(ERR_CAUGHT);
        }
        RLC_FINALLY {
                bn_free(k);
                fp2_free(t);
                ep2_free(q);
        }
}


void ep2_map_dst(ep2_t p, const uint8_t *msg, int len, const uint8_t *dst, int dst_len) {

        /* enough space for two field elements plus extra bytes for uniformity */
        const int len_per_elm = (FP_PRIME + ep_param_level() + 7) / 8;
        uint8_t *pseudo_random_bytes = RLC_ALLOCA(uint8_t, 4 * len_per_elm);

        RLC_TRY {

                /* XXX(rsw) See note in ep/relic_ep_map.c about using MD_MAP. */
                /* hash to a pseudorandom string using md_xmd */
//                printf("\n");
//                printf("len %d\n",len);
//                for(int i=0; i < len ; i++ ){
//                printf(" %" PRIu64 " ", msg[i]);
//                }
                md_xmd(pseudo_random_bytes, 4 * len_per_elm, msg, len, dst, dst_len);
//                printf("\n");
 //               printf(" 4 * len_per_elm: %d\n", 4 * len_per_elm);
//                printf("\n");
//                for(int j = 0; j < 4 * len_per_elm; j++) {
//                    printf("%02x", pseudo_random_bytes[4 * len_per_elm - 1 - j]);
//                }
                ep2_map_from_field(p, pseudo_random_bytes, 2 * len_per_elm);
                printf("\nThe results is: \n");
                ep2_print(p);
        }
        RLC_CATCH_ANY {
                RLC_THROW(ERR_CAUGHT);
        }
        RLC_FINALLY {
                RLC_FREE(pseudo_random_bytes);
        }
}

void ep2_map(ep2_t p, const uint8_t *msg, int len) {
	ep2_map_dst(p, msg, len, (const uint8_t *)"RELIC", 5);
}
