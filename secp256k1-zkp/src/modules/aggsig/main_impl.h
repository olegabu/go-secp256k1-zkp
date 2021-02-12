/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra, Pieter Wuille                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_AGGSIG_MAIN_
#define _SECP256K1_MODULE_AGGSIG_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_aggsig.h"
#include "hash.h"

/* Compute sighash for a single-signer */
static int secp256k1_compute_sighash_single(const secp256k1_context *ctx, secp256k1_scalar *r, const secp256k1_pubkey *pubnonce, const secp256k1_pubkey *pubkey, const unsigned char *msghash32) {
    unsigned char output[32];
    unsigned char buf[33];
    size_t buflen = sizeof(buf);
    int overflow;

    secp256k1_sha256 hasher;
    secp256k1_sha256_initialize(&hasher);

    /* Encode public nonce */
    CHECK(secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, pubnonce, SECP256K1_EC_COMPRESSED));
    secp256k1_sha256_write(&hasher, buf+1, 32);

    /* Encode public key */
    if (pubkey != NULL) {
      buflen = sizeof(buf);
      CHECK(secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, pubkey, SECP256K1_EC_COMPRESSED));
      secp256k1_sha256_write(&hasher, buf, 33);
    }

    /* Encode message */
    secp256k1_sha256_write(&hasher, msghash32, 32);

    /* Finish */
    secp256k1_sha256_finalize(&hasher, output);
    secp256k1_scalar_set_b32(r, output, &overflow);
    return !overflow;
}

/* Compute the hash of all the data that every pubkey needs to sign */
static void secp256k1_compute_prehash(const secp256k1_context *ctx, unsigned char *output, const secp256k1_pubkey *pubkeys, size_t n_pubkeys, const secp256k1_fe *nonce_ge_x, const unsigned char *msghash32) {
    size_t i;
    unsigned char buf[33];
    size_t buflen = sizeof(buf);
    secp256k1_sha256 hasher;
    secp256k1_sha256_initialize(&hasher);

    /* Encode nonce */
    secp256k1_fe_get_b32(buf, nonce_ge_x);
    secp256k1_sha256_write(&hasher, buf, 32);

    /* Encode pubkeys */
    for (i = 0; i < n_pubkeys; i++) {
        CHECK(secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, &pubkeys[i], SECP256K1_EC_COMPRESSED));
        secp256k1_sha256_write(&hasher, buf, sizeof(buf));
    }

    /* Encode message */
    secp256k1_sha256_write(&hasher, msghash32, 32);

    /* Finish */
    secp256k1_sha256_finalize(&hasher, output);
}

/* Add the index to the above hash to customize it for each pubkey */
static int secp256k1_compute_sighash(secp256k1_scalar *r, const unsigned char *prehash, size_t index) {
    unsigned char output[32];
    int overflow;
    secp256k1_sha256 hasher;
    secp256k1_sha256_initialize(&hasher);
    /* Encode index as a UTF8-style bignum */
    while (index > 0) {
        unsigned char ch = index & 0x7f;
        secp256k1_sha256_write(&hasher, &ch, 1);
        index >>= 7;
    }
    secp256k1_sha256_write(&hasher, prehash, 32);
    secp256k1_sha256_finalize(&hasher, output);
    secp256k1_scalar_set_b32(r, output, &overflow);
    return !overflow;
}

int secp256k1_aggsig_generate_nonce_single(const secp256k1_context* ctx, secp256k1_scalar *secnonce, secp256k1_gej* pubnonce, secp256k1_rfc6979_hmac_sha256* rng) {
    int retry;
    unsigned char data[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(secnonce != NULL);
    ARG_CHECK(pubnonce != NULL);
    ARG_CHECK(rng != NULL);

    /* generate nonce from the RNG */
    do {
        secp256k1_rfc6979_hmac_sha256_generate(rng, data, 32);
        secp256k1_scalar_set_b32(secnonce, data, &retry);
        retry = secp256k1_scalar_is_zero(secnonce);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > Fp. */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, pubnonce, secnonce);
    memset(data, 0, 32);  /* TODO proper clear */
    /* Negate nonce if needed to get y to be a quadratic residue */
    if (!secp256k1_gej_has_quad_y_var(pubnonce)) {
        secp256k1_scalar_negate(secnonce, secnonce);
        secp256k1_gej_neg(pubnonce, pubnonce);
    }
    return 1;
}

int secp256k1_aggsig_export_secnonce_single(const secp256k1_context* ctx, unsigned char* secnonce32, const unsigned char* seed) {
    secp256k1_scalar secnonce;
    secp256k1_gej pubnonce;
    secp256k1_rfc6979_hmac_sha256 rng;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(secnonce32 != NULL);
    secp256k1_rfc6979_hmac_sha256_initialize(&rng, seed, 32);

    if (secp256k1_aggsig_generate_nonce_single(ctx, &secnonce, &pubnonce, &rng) == 0){
       return 0;
    }

    secp256k1_scalar_get_b32(secnonce32, &secnonce);
    return 1;
}

int secp256k1_aggsig_sign_single(const secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const unsigned char *seckey32,
    const unsigned char* secnonce32,
    const unsigned char* extra32,
    const secp256k1_pubkey* pubnonce_for_e,
    const secp256k1_pubkey* pubnonce_total,
    const secp256k1_pubkey* pubkey_for_e,
    const unsigned char* seed){

    secp256k1_scalar sighash;
    secp256k1_rfc6979_hmac_sha256 rng;
    secp256k1_scalar sec;
    secp256k1_ge tmp_ge;
    secp256k1_ge total_tmp_ge;
    secp256k1_gej pubnonce_j;
    secp256k1_gej pubnonce_total_j;
    secp256k1_pubkey pub_tmp;

    secp256k1_scalar secnonce;
    secp256k1_ge final;
    int overflow;
    int retry;
    secp256k1_scalar tmp_scalar;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(seckey32 != NULL);
    ARG_CHECK(seed != NULL);

    /* generate nonce if needed */
    if (secnonce32==NULL){
        secp256k1_rfc6979_hmac_sha256_initialize(&rng, seed, 32);
        if (secp256k1_aggsig_generate_nonce_single(ctx, &secnonce, &pubnonce_j, &rng) == 0){
            return 0;
        }
        secp256k1_rfc6979_hmac_sha256_finalize(&rng);
        secp256k1_ge_set_gej(&tmp_ge, &pubnonce_j);
    } else {
        secp256k1_scalar_set_b32(&secnonce, secnonce32, &retry);
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pubnonce_j, &secnonce);
        secp256k1_ge_set_gej(&tmp_ge, &pubnonce_j);

        if (pubnonce_total!=NULL) {
            secp256k1_gej_set_infinity(&pubnonce_total_j);
            secp256k1_pubkey_load(ctx, &total_tmp_ge, pubnonce_total);
            secp256k1_gej_add_ge(&pubnonce_total_j, &pubnonce_total_j, &total_tmp_ge);
            if (!secp256k1_gej_has_quad_y_var(&pubnonce_total_j)) {
                secp256k1_scalar_negate(&secnonce, &secnonce);
            }
        } else {
            if (!secp256k1_gej_has_quad_y_var(&pubnonce_j)) {
                secp256k1_scalar_negate(&secnonce, &secnonce);
                secp256k1_gej_neg(&pubnonce_j, &pubnonce_j);
                secp256k1_ge_neg(&tmp_ge, &tmp_ge);
            }
        }
    }

    secp256k1_fe_normalize(&tmp_ge.x);

    /* compute signature hash (in the simple case just message+pubnonce+pubkey) */
    if (pubnonce_for_e != NULL) {
        secp256k1_compute_sighash_single(ctx, &sighash, pubnonce_for_e, pubkey_for_e, msg32);
    } else {
        secp256k1_pubkey_save(&pub_tmp, &tmp_ge);
        secp256k1_compute_sighash_single(ctx, &sighash, &pub_tmp, pubkey_for_e, msg32);
    }
    /* calculate signature */
    secp256k1_scalar_set_b32(&sec, seckey32, &overflow);
    if (overflow) {
        secp256k1_scalar_clear(&sec);
        return 0;
    }

    secp256k1_scalar_mul(&sec, &sec, &sighash);
    secp256k1_scalar_add(&sec, &sec, &secnonce);

    if (extra32 != NULL) {
        /* add extra scalar */
        secp256k1_scalar_set_b32(&tmp_scalar, extra32, &overflow);
        if (overflow) {
            secp256k1_scalar_clear(&sec);
            return 0;
        }
        secp256k1_scalar_add(&sec, &sec, &tmp_scalar);
    }

    /* finalize */
    secp256k1_ge_set_gej(&final, &pubnonce_j);
    secp256k1_fe_normalize_var(&final.x);
    secp256k1_fe_get_b32(sig64, &final.x);
    secp256k1_scalar_get_b32(sig64 + 32, &sec);

    secp256k1_scalar_clear(&sec);

    return 1;
}

int secp256k1_aggsig_add_signatures_single(const secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char** sigs,
    size_t num_sigs,
    const secp256k1_pubkey* pubnonce_total) {

    secp256k1_scalar s;
    secp256k1_ge final;
    secp256k1_scalar tmp;
    secp256k1_ge noncesum_pt;
    secp256k1_gej pubnonce_total_j;
    size_t i;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(sigs != NULL);
    for (i=0;i<num_sigs;i++) ARG_CHECK(sigs[i] != NULL);
    ARG_CHECK(pubnonce_total != NULL);
    (void) ctx;

    /* Add signature portions together */
    secp256k1_scalar_set_int(&s, 0);
    for (i = 0; i < num_sigs; i++){
        secp256k1_scalar_set_b32(&tmp, sigs[i] + 32, &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_add(&s, &s, &tmp);
    }

    /* nonces should already be totalled */
    secp256k1_gej_set_infinity(&pubnonce_total_j);
    secp256k1_pubkey_load(ctx, &noncesum_pt, pubnonce_total);
    secp256k1_gej_add_ge(&pubnonce_total_j, &pubnonce_total_j, &noncesum_pt);
    if (!secp256k1_gej_has_quad_y_var(&pubnonce_total_j)) {
        secp256k1_gej_neg(&pubnonce_total_j, &pubnonce_total_j);
    }

    secp256k1_ge_set_gej(&final, &pubnonce_total_j);
    secp256k1_fe_normalize_var(&final.x);
    secp256k1_fe_get_b32(sig64, &final.x);
    secp256k1_scalar_get_b32(sig64 + 32, &s);
    return 1;
}

typedef struct {
    const secp256k1_context *ctx;
    unsigned char prehash[32];
    secp256k1_scalar single_hash;
    const secp256k1_pubkey *pubkeys;
} secp256k1_verify_callback_data;

static int secp256k1_aggsig_verify_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_verify_callback_data *cbdata = (secp256k1_verify_callback_data*) data;

    if (secp256k1_compute_sighash(sc, cbdata->prehash, idx) == 0) {
        return 0;
    }
    secp256k1_scalar_negate(sc, sc);
    secp256k1_pubkey_load(cbdata->ctx, pt, &cbdata->pubkeys[idx]);
    return 1;
}

int secp256k1_aggsig_verify(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const unsigned char *sig64, const unsigned char *msg32, const secp256k1_pubkey *pubkeys, size_t n_pubkeys) {
    secp256k1_scalar g_sc;
    secp256k1_gej pk_sum;
    secp256k1_ge pk_sum_ge;
    secp256k1_fe r_x;
    int overflow;
    secp256k1_verify_callback_data cbdata;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkeys != NULL);
    (void) ctx;

    if (n_pubkeys == 0) {
        return 0;
    }

    /* extract R */
    if (!secp256k1_fe_set_b32(&r_x, sig64)) {
        return 0;
    }

    /* extract s */
    secp256k1_scalar_set_b32(&g_sc, sig64 + 32, &overflow);
    if (overflow) {
        return 0;
    }

    /* Populate callback data */
    cbdata.ctx = ctx;
    cbdata.pubkeys = pubkeys;
    secp256k1_compute_prehash(ctx, cbdata.prehash, pubkeys, n_pubkeys, &r_x, msg32);

    /* Compute sum sG - e_i*P_i, which should be R */
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &pk_sum, &g_sc, secp256k1_aggsig_verify_callback, &cbdata, n_pubkeys)) {
        return 0;
    }

    /* Check sum */
    secp256k1_ge_set_gej(&pk_sum_ge, &pk_sum);
    return secp256k1_fe_equal_var(&r_x, &pk_sum_ge.x) &&
           secp256k1_gej_has_quad_y_var(&pk_sum);
}

int secp256k1_aggsig_build_scratch_and_verify(const secp256k1_context* ctx, 
                                              const unsigned char *sig64,
                                              const unsigned char *msg32,
                                              const secp256k1_pubkey *pubkeys, 
                                              size_t n_pubkeys) {
    /* just going to inefficiently allocate every time */
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024*4096);
    int returnval=secp256k1_aggsig_verify(ctx, scratch, sig64, msg32, pubkeys, n_pubkeys);
    secp256k1_scratch_space_destroy(ctx, scratch);
    return returnval;
}

static int secp256k1_aggsig_verify_callback_single(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_verify_callback_data *cbdata = (secp256k1_verify_callback_data*) data;
    secp256k1_scalar_negate(sc, &cbdata->single_hash);
    secp256k1_pubkey_load(cbdata->ctx, pt, &cbdata->pubkeys[idx]);
    return 1;
}

int secp256k1_aggsig_verify_single(
    const secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubnonce,
    const secp256k1_pubkey *pubkey,
    const secp256k1_pubkey *pubkey_total,
    const secp256k1_pubkey *extra_pubkey,
    const int is_partial){

    secp256k1_scalar g_sc;
    secp256k1_fe r_x;
    secp256k1_gej pk_sum;
    secp256k1_ge pk_sum_ge;
    secp256k1_scalar sighash;
    secp256k1_scratch_space *scratch;
    secp256k1_verify_callback_data cbdata;
    secp256k1_ge tmp_ge;
    secp256k1_pubkey tmp_pk;

    int overflow;
    int return_check=0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);

    /* extract R */
    if (!secp256k1_fe_set_b32(&r_x, sig64)) {
        return 0;
    }

    /* extract s */
    secp256k1_scalar_set_b32(&g_sc, sig64 + 32, &overflow);
    if (overflow) {
        return 0;
    }

    /* compute e = sighash */
    if (pubnonce != NULL) {
        secp256k1_compute_sighash_single(ctx, &sighash, pubnonce, pubkey_total, msg32);
    } else {
        secp256k1_ge_set_xquad(&tmp_ge, &r_x);
        secp256k1_pubkey_save(&tmp_pk, &tmp_ge);
        secp256k1_compute_sighash_single(ctx, &sighash, &tmp_pk, pubkey_total, msg32);
    }

    /* Populate callback data */
    cbdata.ctx = ctx;
    cbdata.pubkeys = pubkey;
    cbdata.single_hash = sighash;

    scratch = secp256k1_scratch_space_create(ctx, 1024*4096);
    if (scratch == NULL){
        return 0;
    }
    
    /* Compute sG - eP, which should be R */
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &pk_sum, &g_sc, secp256k1_aggsig_verify_callback_single, &cbdata, 1)) {
        secp256k1_scratch_space_destroy(ctx, scratch);
        return 0;
    }

    secp256k1_scratch_space_destroy(ctx, scratch);

    if (extra_pubkey != NULL) {
        /* Subtract an extra public key */
        secp256k1_pubkey_load(ctx, &tmp_ge, extra_pubkey);
        secp256k1_ge_neg(&tmp_ge, &tmp_ge);
        secp256k1_gej_add_ge(&pk_sum, &pk_sum, &tmp_ge);
    }

    secp256k1_ge_set_gej(&pk_sum_ge, &pk_sum);

    return_check = secp256k1_fe_equal_var(&r_x, &pk_sum_ge.x);
    if (!is_partial){
        return return_check && secp256k1_gej_has_quad_y_var(&pk_sum);
    } else {
        return return_check;
    }

}

#endif
