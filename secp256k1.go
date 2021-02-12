package secp256k1

/*
#cgo CFLAGS: -I${SRCDIR}/secp256k1-zkp -I${SRCDIR}/secp256k1-zkp/src
#include <stdlib.h>
#include <stdint.h>
#define USE_BASIC_CONFIG 1
#include "basic-config.h"
#define ENABLE_MODULE_ECDH 1
#define ENABLE_MODULE_RECOVERY 1
#define ENABLE_MODULE_GENERATOR 1
#define ENABLE_MODULE_COMMITMENT 1
#define ENABLE_MODULE_RANGEPROOF 1
#define ENABLE_MODULE_BULLETPROOF 1
#define ENABLE_MODULE_AGGSIG 1
#define ENABLE_MODULE_SCHNORRSIG 1
#define ENABLE_MODULE_WHITELIST 1
#define ENABLE_MODULE_SURJECTIONPROOF 1
#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_MUSIG 1
#define ECMULT_GEN_PREC_BITS 4
#include "src/secp256k1.c"
#include "src/testrand_impl.h"
#include "src/modules/musig/main_impl.h"
static secp256k1_pubkey** makePubkeyArray(int size) { return calloc(sizeof(secp256k1_pubkey*), size); }
static void setArrayPubkey(secp256k1_pubkey **a, secp256k1_pubkey *pubkey, int n) { a[n] = pubkey; }
static void freePubkeyArray(secp256k1_pubkey * *a) { free(a); }
static const unsigned char** makeBytesArray(int size) { return !size ? NULL : calloc(sizeof(unsigned char*), size); }
static void setBytesArray(unsigned char** a, unsigned char* v, int i) { if (a) a[i] = v; }
static unsigned char* getBytesArray(unsigned char** a, int i) { return !a ? NULL : a[i]; }
static void freeBytesArray(unsigned char** a) { if (a) free(a); }
void random_scalar_order256(unsigned char *out) {
	do {
        int overflow = 0;
        secp256k1_scalar num;
        secp256k1_testrand256(out);
        secp256k1_scalar_set_b32(&num, out, &overflow);
		if (!overflow && !secp256k1_scalar_is_zero(&num)) break;
    }
	while (1);
}
int blind_value_generator_blind_sum(uint64_t v, const unsigned char* ra, unsigned char* r) {
 	int success = 0;
    int overflow = 0;
    secp256k1_scalar tmp, vra;
    secp256k1_scalar_set_u64(&vra, v);
 	secp256k1_scalar_set_b32(&tmp, ra, &overflow);
    if (!overflow) {
        secp256k1_scalar_mul(&vra, &vra, &tmp); // vra = v * ra
        secp256k1_scalar_set_b32(&tmp, r, &overflow);
        if (!overflow) {
            secp256k1_scalar_add(&vra, &vra, &tmp); // result = vra + r
            secp256k1_scalar_get_b32(r, &vra); // pass the result back in r
            success = 1;
        }
 	}
    secp256k1_scalar_clear(&vra);
    secp256k1_scalar_clear(&tmp);
    return success;
}
int secp256k1_pedersen_commit_sum(const secp256k1_context *ctx, secp256k1_pedersen_commitment *commit_out,
	const secp256k1_pedersen_commitment *const *commits, size_t pcnt, const secp256k1_pedersen_commitment *const *ncommits, size_t ncnt) {
    secp256k1_gej accj;
    secp256k1_ge add;
    size_t i;
    int ret = 0;
    if (ctx == NULL) return 0;              // VERIFY_CHECK(ctx != NULL);
    if (pcnt && commits == NULL) return 0;  // ARG_CHECK(!pcnt || (commits != NULL));
    if (ncnt && ncommits == NULL) return 0; // ARG_CHECK(!ncnt || (ncommits != NULL));
    if (commit_out == NULL) return 0;       // ARG_CHECK(commit_out != NULL);
    (void) ctx;
    secp256k1_gej_set_infinity(&accj);
    for (i = 0; i < ncnt; i++) {
        secp256k1_pedersen_commitment_load(&add, ncommits[i]);
        secp256k1_gej_add_ge_var(&accj, &accj, &add, NULL);
    }
    secp256k1_gej_neg(&accj, &accj);
    for (i = 0; i < pcnt; i++) {
        secp256k1_pedersen_commitment_load(&add, commits[i]);
        secp256k1_gej_add_ge_var(&accj, &accj, &add, NULL);
    }
    if (!secp256k1_gej_is_infinity(&accj)) {
        secp256k1_ge acc;
        secp256k1_ge_set_gej(&acc, &accj);
        secp256k1_pedersen_commitment_save(commit_out, &acc);
        ret = 1;
    }
    return ret;
}
int secp256k1_pedersen_commitment_to_pubkey(secp256k1_pubkey *pubkey, const secp256k1_pedersen_commitment *commit) {
    secp256k1_ge Q;
    secp256k1_fe fe;
    memset(pubkey, 0, sizeof(*pubkey));
    secp256k1_fe_set_b32(&fe, &commit->data[1]);
    secp256k1_ge_set_xquad(&Q, &fe);
    if (commit->data[0] & 1) {
        secp256k1_ge_neg(&Q, &Q);
    }
    secp256k1_pubkey_save(pubkey, &Q);
    secp256k1_ge_clear(&Q);
    return 1;
}
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"
)

const (
	// Flags to pass to secp256k1_context_create.
	ContextNone   = uint(C.SECP256K1_CONTEXT_NONE)
	ContextSign   = uint(C.SECP256K1_CONTEXT_SIGN)
	ContextVerify = uint(C.SECP256K1_CONTEXT_VERIFY)
	ContextBoth   = uint(C.SECP256K1_CONTEXT_SIGN | C.SECP256K1_CONTEXT_VERIFY)

	// Flags for EcPubkeySerialize
	EcCompressed   = uint(C.SECP256K1_EC_COMPRESSED)
	EcUncompressed = uint(C.SECP256K1_EC_UNCOMPRESSED)

	// Length of elements byte representations
	LenCompressed   int = 33
	LenUncompressed int = 65
	LenMsgHash      int = 32
	LenPrivateKey   int = 32
	LenCompactSig   int = 64
	LenMaxDerSig    int = 72

	// Errors returned by functions
	ErrorPrivateKeyNull                string = "Private key cannot be null"
	ErrorPrivateKeyInvalid             string = "Invalid private key"
	ErrorPublicKeyNull                 string = "Public key cannot be null"
	ErrorEcdsaSignatureNull            string = "Signature cannot be null"
	ErrorEcdsaRecoverableSignatureNull string = "Recoverable signature cannot be null"
	ErrorEcdh                          string = "Unable to do ECDH"
	ErrorPublicKeyCreate               string = "Unable to produce public key"
	ErrorPublicKeyCombine              string = "Unable to combine public keys"

	ErrorTweakSize      string = "Tweak must be exactly 32 bytes"
	ErrorMsg32Size      string = "Message hash must be exactly 32 bytes"
	ErrorPrivateKeySize string = "Private key must be exactly 32 bytes"
	ErrorPublicKeySize  string = "Public key must be 33 or 65 bytes"

	ErrorTweakingPublicKey  string = "Unable to tweak this public key"
	ErrorTweakingPrivateKey string = "Unable to tweak this private key"

	ErrorProducingSignature            string = "Unable to produce signature"
	ErrorProducingRecoverableSignature string = "Unable to produce recoverable signature"

	ErrorCompactSigSize  string = "Compact signature must be exactly 64 bytes"
	ErrorCompactSigParse string = "Unable to parse this compact signature"

	ErrorDerSigParse string = "Unable to parse this DER signature"

	ErrorRecoverableSigParse string = "Unable to parse this recoverable signature"
	ErrorRecoveryFailed      string = "Failed to recover public key"

	ErrorPublicKeyParse string = "Unable to parse this public key"
)

// Context wraps a *secp256k1_context, required to use all
// functions. It can be initialized for signing, verification,
// or both.
type Context struct {
	ctx *C.secp256k1_context
}

// PublicKey wraps a *secp256k1_pubkey, which contains the prefix plus
// the X+Y coordidnates
type PublicKey struct {
	pk *C.secp256k1_pubkey
}

// EcdsaSignature wraps a *secp256k1_ecdsa_signature, containing the R
// and S values.
type EcdsaSignature struct {
	sig *C.secp256k1_ecdsa_signature
}

// EcdsaRecoverableSignature wraps a *secp256k1_ecdsa_recoverable_signature
// which contains the signature, and information about public key recovery.
type EcdsaRecoverableSignature struct {
	sig *C.secp256k1_ecdsa_recoverable_signature
}

// Helper methods for this library

func newContext() *Context {
	var ctx *C.secp256k1_context
	return &Context{ctx}
}

func newPublicKey() *PublicKey {
	return &PublicKey{
		pk: &C.secp256k1_pubkey{},
	}
}

func newEcdsaSignature() *EcdsaSignature {
	return &EcdsaSignature{
		sig: &C.secp256k1_ecdsa_signature{},
	}
}

func newEcdsaRecoverableSignature() *EcdsaRecoverableSignature {
	return &EcdsaRecoverableSignature{
		sig: &C.secp256k1_ecdsa_recoverable_signature{},
	}
}

var ctxmap map[uint]*Context

func init() {
	//seed := make([]byte, 16)
	//rand.Read(seed)
	//C.secp256k1_rand_seed(cBuf(seed))
	ctxmap = make(map[uint]*Context)
}

// Begin bindings for secp256k1.h

// ContextCreate produces a new *Context, initialized with a bitmask
// of flags depending on it's intended usage. The supported flags
// are currently ContextSign and ContextVerify. Although expressed
// in the return type signature, the function does not currently
// return an error.
func ContextCreate(flags uint) (*Context, error) {
	context := newContext()
	context.ctx = C.secp256k1_context_create(C.uint(flags))
	return context, nil
}

// ContextClone makes a copy of the provided *Context. The provided
// context must not be NULL.
func ContextClone(ctx *Context) (*Context, error) {
	other := newContext()
	other.ctx = C.secp256k1_context_clone(ctx.ctx)
	return other, nil
}

// ContextDestroy destroys the context. The provided context must not
// be NULL.
func ContextDestroy(ctx *Context) {
	C.secp256k1_context_destroy(ctx.ctx)
}

// ContextRandomize accepts a [32]byte seed in order to update the context
// randomization. NULL may be passed to reset to initial state. The context
// pointer must not be null.
func ContextRandomize(ctx *Context, seed32 [32]byte) int {
	return int(C.secp256k1_context_randomize(ctx.ctx, cBuf(seed32[:])))
}

func SharedContext(flags uint) (context *Context) {
	flags = flags & ContextBoth
	context, exists := ctxmap[flags]
	if !exists {
		var err error
		context, err = ContextCreate(flags)
		if err != nil {
			panic(fmt.Sprintf("error creating default context object (flags: %d, error: %s)", flags, err))
		}
		ctxmap[flags] = context
	}

	return
}

// EcPubkeyParse deserializes a variable-length public key into a *Pubkey
// object. The function will reject any input of zero bytes in length.
// This function supports parsing compressed (33 bytes, header byte 0x02 or
// 0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes,
// header byte 0x06 or 0x07) format public keys. The return code is 1 if
// the public key was fully valid, or 0 if the public key was invalid or
// could not be parsed.
func EcPubkeyParse(ctx *Context, publicKey []byte) (int, *PublicKey, error) {
	l := len(publicKey)
	if l < 1 {
		return 0, nil, errors.New(ErrorPublicKeySize)
	}

	pk := newPublicKey()
	result := int(C.secp256k1_ec_pubkey_parse(ctx.ctx, pk.pk, cBuf(publicKey), C.size_t(l)))
	if result != 1 {
		return result, nil, errors.New(ErrorPublicKeyParse)
	}
	return result, pk, nil
}

// EcPubkeySerialize serializes a pubkey object into a []byte. The output
// is an array of 65-bytes (if compressed==0), or 33-bytes (if compressed==1).
// Use EcCompressed or EcUncompressed to request a certain format. The
// function will always return 1, because the only
// public key objects are valid ones.
func EcPubkeySerialize(ctx *Context, publicKey *PublicKey, flags uint) (int, []byte, error) {
	var size int
	if flags == EcCompressed {
		size = LenCompressed
	} else {
		size = LenUncompressed
	}

	output := make([]C.uchar, size)
	outputLen := C.size_t(size)
	result := int(C.secp256k1_ec_pubkey_serialize(ctx.ctx, &output[0], &outputLen, publicKey.pk, C.uint(flags)))
	return result, goBytes(output, C.int(outputLen)), nil
}

// EcdsaSignatureParseCompact parses an ECDSA signature in compact (64
// bytes) format. The return code is 1 when the signature could be
// parsed, 0 otherwise. The signature must consist of a 32-byte big
// endian R value, followed by a 32-byte big endian S value. If R or S fall
// outside of [0..order-1], the encoding is invalid. R and S with value 0
// are allowed in the encoding. After the call, sig will always be
// initialized. If parsing failed or R or S are zero, the resulting sig
// value is guaranteed to fail validation for any message and public key.
func EcdsaSignatureParseCompact(ctx *Context, signature []byte) (int, *EcdsaSignature, error) {
	if len(signature) != LenCompactSig {
		return 0, nil, errors.New(ErrorCompactSigSize)
	}

	sig := newEcdsaSignature()
	result := int(C.secp256k1_ecdsa_signature_parse_compact(ctx.ctx, sig.sig,
		(*C.uchar)(unsafe.Pointer(&signature[0])),
	))
	if result != 1 {
		return result, nil, errors.New(ErrorCompactSigParse)
	}
	return result, sig, nil
}

// Serialize an ECDSA signature in compact (64 byte) format. Return code is
// always 1. See EcdsaSignatureParseCompact for details about the encoding.
func EcdsaSignatureSerializeCompact(ctx *Context, sig *EcdsaSignature) (int, []byte, error) {
	output := make([]C.uchar, LenCompactSig)
	result := int(C.secp256k1_ecdsa_signature_serialize_compact(ctx.ctx, &output[0], sig.sig))
	return result, goBytes(output, C.int(LenCompactSig)), nil
}

// Parse a DER ECDSA signature. Returns 1 when the signature
// could be parsed, 0 otherwise. This function will accept any
// valid DER encoded signature, even if the encoded numbers are
// out of range.
// After the call, sig will always be initialized. If parsing failed or the
// encoded numbers are out of range, signature validation with it is
// guaranteed to fail for every message and public key.
func EcdsaSignatureParseDer(ctx *Context, signature []byte) (int, *EcdsaSignature, error) {
	sig := newEcdsaSignature()

	result := int(C.secp256k1_ecdsa_signature_parse_der(ctx.ctx, sig.sig,
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		(C.size_t)(len(signature))))

	if result != 1 {
		return result, nil, errors.New(ErrorDerSigParse)
	}
	return result, sig, nil
}

// Serialize an ECDSA signature in DER format. The return code for this
// function _should_ always return 1, since the serializedSig is
// initialized to LenMaxDerSig. If some day it doesn't, it's serious.
func EcdsaSignatureSerializeDer(ctx *Context, sig *EcdsaSignature) (int, []byte, error) {
	serializedSig := make([]C.uchar, LenMaxDerSig)
	outputLen := C.size_t(len(serializedSig))
	result := int(C.secp256k1_ecdsa_signature_serialize_der(ctx.ctx, &serializedSig[0], &outputLen, sig.sig))
	return result, goBytes(serializedSig, C.int(outputLen)), nil
}

// Verify an ECDSA signature. Return code is 1 for a correct signature,
// or 0 if incorrect. To avoid accepting malleable signature, only ECDSA
// signatures in lower-S form are accepted. If you need to accept ECDSA
// sigantures from sources that do not obey this rule, apply
// EcdsaSignatureNormalize() prior to validation (however, this results in
// malleable signatures)
func EcdsaVerify(ctx *Context, sig *EcdsaSignature, msg32 []byte,
	pubkey *PublicKey) (int, error) {
	if len(msg32) != LenMsgHash {
		return 0, errors.New(ErrorMsg32Size)
	}
	result := C.secp256k1_ecdsa_verify(ctx.ctx, sig.sig, cBuf(msg32[:]), pubkey.pk)
	return int(result), nil
}

// Create an ECDSA signature. Return code is 1 if the signature was
// created, or is zero and the error is set if the nonce generation
// function failed, or the private key was invalid. The created
// signature is always in lower-S form. See EcdsaSignatureNormalize for
// details.
func EcdsaSign(ctx *Context, msg32 []byte, seckey []byte) (int, *EcdsaSignature, error) {
	if len(msg32) != LenMsgHash {
		return 0, nil, errors.New(ErrorMsg32Size)
	}
	if len(seckey) != LenPrivateKey {
		return 0, nil, errors.New(ErrorPrivateKeySize)
	}

	signature := newEcdsaSignature()
	result := int(C.secp256k1_ecdsa_sign(ctx.ctx, signature.sig,
		cBuf(msg32[:]), cBuf(seckey[:]), nil, nil))

	if result != 1 {
		return result, nil, errors.New(ErrorProducingSignature)
	}

	return result, signature, nil
}

// Verify a secret key. Returns 1 if the secret key is valid, or 0 if an
// error occured or the key was empty.
func EcSeckeyVerify(ctx *Context, seckey []byte) (int, error) {
	if len(seckey) < 1 {
		return 0, errors.New(ErrorPrivateKeyNull)
	}
	result := int(C.secp256k1_ec_seckey_verify(ctx.ctx, cBuf(seckey[:])))
	if result != 1 {
		return result, errors.New(ErrorPrivateKeyInvalid)
	}
	return result, nil
}

// EcPubkeyCreate will compute the public key for a secret key. The
// return code is 1 and the key returned if the secret was valid.
// Otherwise, the return code is 0, and an error is returned. The key
// length must be 32-bytes.
func EcPubkeyCreate(ctx *Context, seckey []byte) (int, *PublicKey, error) {
	if len(seckey) != LenPrivateKey {
		return 0, nil, errors.New(ErrorPrivateKeySize)
	}

	pk := newPublicKey()
	result := int(C.secp256k1_ec_pubkey_create(ctx.ctx, pk.pk, cBuf(seckey[:])))
	if result != 1 {
		return result, nil, errors.New(ErrorPublicKeyCreate)
	}
	return result, pk, nil
}

// EcPrivkeyNegate will negate a public key in place. The return code is
// 1 if the operation was successful, or 0 if the length was invalid.
func EcPrivkeyNegate(ctx *Context, seckey []byte) (int, error) {
	if len(seckey) != LenPrivateKey {
		return 0, errors.New(ErrorPrivateKeySize)
	}

	result := int(C.secp256k1_ec_privkey_negate(ctx.ctx, (*C.uchar)(unsafe.Pointer(&seckey[0]))))
	return result, nil
}

// EcPubkeyNegate will negate a public key object in place. The return code
// is always 1.
func EcPubkeyNegate(ctx *Context, pubkey *PublicKey) (int, error) {
	result := int(C.secp256k1_ec_pubkey_negate(ctx.ctx, pubkey.pk))
	return result, nil
}

// EcPrivkeyTweakAdd modifies the provided `seckey` by adding tweak to
// it. The return code is 0 if `tweak` was out of range (chance of
// around 1 in 2^128 for uniformly random 32-byte arrays), or if the
// resulting private key would be invalid (only when the tweak is the
// complement of the private key). The return code is 1 otherwise.
func EcPrivkeyTweakAdd(ctx *Context, seckey []byte, tweak []byte) (int, error) {
	if len(tweak) != LenPrivateKey {
		return 0, errors.New(ErrorTweakSize)
	}
	if len(seckey) != LenPrivateKey {
		return 0, errors.New(ErrorPrivateKeySize)
	}

	result := int(C.secp256k1_ec_privkey_tweak_add(ctx.ctx, (*C.uchar)(unsafe.Pointer(&seckey[0])), cBuf(tweak[:])))
	if result != 1 {
		return result, errors.New(ErrorTweakingPrivateKey)
	}
	return result, nil
}

// Tweak a private key by multiplying it by a tweak. The return code is 0
// if the tweak was out of range (chance of around 1 in 2^128 for uniformly
// random 32-byte arrays) or zero. The code is 1 otherwise.
func EcPrivkeyTweakMul(ctx *Context, seckey []byte, tweak []byte) (int, error) {
	if len(tweak) != LenPrivateKey {
		return 0, errors.New(ErrorTweakSize)
	}
	if len(seckey) != LenPrivateKey {
		return 0, errors.New(ErrorPrivateKeySize)
	}

	result := int(C.secp256k1_ec_privkey_tweak_mul(ctx.ctx, (*C.uchar)(unsafe.Pointer(&seckey[0])), cBuf(tweak[:])))
	if result != 1 {
		return result, errors.New(ErrorTweakingPrivateKey)
	}
	return result, nil
}

// Tweak a public key by adding tweak times the generator to it. The
// return code is 0 if the tweak was out of range (chance of around 1 in
// 2^128 for uniformly random 32-byte arrays) or if the resulting public
// key would be invalid. The return code is 1 otherwise.
func EcPubkeyTweakAdd(ctx *Context, pk *PublicKey, tweak []byte) (int, error) {
	if len(tweak) != LenPrivateKey {
		return 0, errors.New(ErrorTweakSize)
	}

	result := int(C.secp256k1_ec_pubkey_tweak_add(ctx.ctx, pk.pk, cBuf(tweak)))
	if result != 1 {
		return result, errors.New(ErrorTweakingPublicKey)
	}
	return result, nil
}

// Tweak a public key by multiplying it by a tweak. The return code is 0
// if the tweak was out of range (chance of around 1 in 2^128 for uniformly
// random 32-byte arrays) or zero. The code is 1 otherwise.
func EcPubkeyTweakMul(ctx *Context, pk *PublicKey, tweak []byte) (int, error) {
	if len(tweak) != LenPrivateKey {
		return 0, errors.New(ErrorTweakSize)
	}

	result := int(C.secp256k1_ec_pubkey_tweak_mul(ctx.ctx, pk.pk, cBuf(tweak)))
	if result != 1 {
		return result, errors.New(ErrorTweakingPublicKey)
	}
	return result, nil
}

// EcPubkeyCombine will compute sum of all the provided public keys,
// returning a new point. The error code is 1 if the sum is valid, 0
// otherwise. There must be at least one public key.
func EcPubkeyCombine(ctx *Context, vPk []*PublicKey) (int, *PublicKey, error) {
	l := len(vPk)
	if l < 1 {
		return 0, nil, errors.New("Must provide at least one public key")
	}

	array := C.makePubkeyArray(C.int(l))
	for i := 0; i < l; i++ {
		C.setArrayPubkey(array, vPk[i].pk, C.int(i))
	}
	defer C.freePubkeyArray(array)

	pkOut := newPublicKey()
	result := int(C.secp256k1_ec_pubkey_combine(ctx.ctx, pkOut.pk, array, C.size_t(l)))
	if result != 1 {
		return result, nil, errors.New(ErrorPublicKeyCombine)
	}
	return result, pkOut, nil
}

// Compute an EC Diffie-Hellman secret in constant time. Return code is
// 1 if exponentiation was successful, or 0 if the scalar was invalid.
func Ecdh(ctx *Context, pubKey *PublicKey, privKey []byte) (int, []byte, error) {
	if len(privKey) != LenPrivateKey {
		return 0, []byte{}, errors.New(ErrorPrivateKeySize)
	}
	secret := make([]byte, LenPrivateKey)
	result := int(C.secp256k1_ecdh(ctx.ctx, cBuf(secret[:]), pubKey.pk, cBuf(privKey[:]), nil, nil))
	if result != 1 {
		return result, []byte{}, errors.New(ErrorEcdh)
	}
	return result, secret, nil
}

// Parse a compact ECDSA signature from the 64-byte signature and recovery
// id (0, 1, 2, or 3). The return code is 1 if successful, 0 otherwise.
func EcdsaRecoverableSignatureParseCompact(ctx *Context, signature []byte, recid int) (int, *EcdsaRecoverableSignature, error) {
	if len(signature) != LenCompactSig {
		return 0, nil, errors.New(ErrorCompactSigSize)
	}

	sig := newEcdsaRecoverableSignature()
	result := int(C.secp256k1_ecdsa_recoverable_signature_parse_compact(ctx.ctx, sig.sig,
		(*C.uchar)(unsafe.Pointer(&signature[0])), C.int(recid)))

	if result != 1 {
		return result, nil, errors.New(ErrorRecoverableSigParse)
	}
	return result, sig, nil
}

// Serialize an ECDSA signature in compact format, returning the []byte
// and the recovery id. Return code is always 1.
func EcdsaRecoverableSignatureSerializeCompact(ctx *Context, sig *EcdsaRecoverableSignature) (int, []byte, int, error) {
	output := make([]C.uchar, LenCompactSig)
	r := C.int(0)
	result := int(C.secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx.ctx, &output[0], &r, sig.sig))
	return result, goBytes(output, C.int(LenCompactSig)), int(r), nil
}

// Convert a recoverable signature into a normal signature. The return code
// is always 1.
func EcdsaRecoverableSignatureConvert(ctx *Context, sig *EcdsaRecoverableSignature) (int, *EcdsaSignature, error) {
	sigOut := newEcdsaSignature()
	result := int(C.secp256k1_ecdsa_recoverable_signature_convert(ctx.ctx, sigOut.sig, sig.sig))
	return result, sigOut, nil
}

// Create a recoverable ECDSA signature. The return code is 1 when the sig
// was created, or 0 if nonce generation failed or the private key was
// invalid.
func EcdsaSignRecoverable(ctx *Context, msg32 []byte, seckey []byte) (int, *EcdsaRecoverableSignature, error) {
	if len(msg32) != LenMsgHash {
		return 0, nil, errors.New(ErrorMsg32Size)
	}
	if len(seckey) != LenPrivateKey {
		return 0, nil, errors.New(ErrorPrivateKeySize)
	}

	recoverable := newEcdsaRecoverableSignature()
	result := int(C.secp256k1_ecdsa_sign_recoverable(ctx.ctx, recoverable.sig, cBuf(msg32), cBuf(seckey), nil, nil))
	if result != 1 {
		return result, nil, errors.New(ErrorProducingRecoverableSignature)
	}
	return result, recoverable, nil

}

// Recover an ECDSA public key from a signature. The return code is 1 if
// the key was successfully recovered (which guarantees a correct
// signature), and is 0 otherwise.
func EcdsaRecover(ctx *Context, sig *EcdsaRecoverableSignature, msg32 []byte) (int, *PublicKey, error) {
	if len(msg32) != LenMsgHash {
		return 0, nil, errors.New(ErrorMsg32Size)
	}
	recovered := newPublicKey()
	result := int(C.secp256k1_ecdsa_recover(ctx.ctx, recovered.pk, sig.sig, cBuf(msg32)))
	if result != 1 {
		return result, nil, errors.New(ErrorRecoveryFailed)
	}
	return result, recovered, nil
}

func cBuf(goSlice []byte) *C.uchar {
	if goSlice == nil {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}

func u64Arr(a []uint64) *C.uint64_t {
	if a == nil {
		return nil
	}
	return (*C.uint64_t)(unsafe.Pointer(&a[0]))
}

func goBytes(cSlice []C.uchar, size C.int) []byte {
	return C.GoBytes(unsafe.Pointer(&cSlice[0]), size)
}

func goUchars(pBytes *C.uchar, size C.int) []byte {
	return C.GoBytes(unsafe.Pointer(pBytes), size)
}

/*func Random256() [32]byte {
	s := make([]byte, 32)
	l, err := rand.Read(s)

	var r [32]byte
	copy(r[:], s[:32])

	if l != 32 || err != nil {
		return r
	}

	return r
}*/
/*
void random_scalar_order256(secp256k1_scalar *num) {
	int overflow = 0;
	do {
		unsigned char b32[32];
		secp256k1_rand256(b32);
		secp256k1_scalar_set_b32(num, b32, &overflow);
	}
	while (overflow || secp256k1_scalar_is_zero(num));
}
*/
// Generate a pseudorandom 32-byte array with long sequences of zero and one bits
func Random256() (rnd32 [32]byte) {
	//C.secp256k1_rand256(cBuf(rnd32[:]))
	C.random_scalar_order256(cBuf(rnd32[:]))
	return
}

// Generate a pseudorandom 32-byte array with long sequences of zero and one bits
// Random sequence generated by this function will not exceed scalar order
func RandomScalarOrder256() (rnd32 [32]byte) {
	C.random_scalar_order256(cBuf(rnd32[:]))
	return
}

func (pubkey *PublicKey) Bytes(context *Context) (bytes []byte) {
	_, bytes, _ = EcPubkeySerialize(context, pubkey, EcCompressed)
	return
}

func (pubkey *PublicKey) BytesUncompressed(context *Context) (bytes []byte) {
	_, bytes, _ = EcPubkeySerialize(context, pubkey, EcUncompressed)
	return
}

func (pubkey *PublicKey) Hex(context *Context) string {
	return hex.EncodeToString(pubkey.Bytes(context))
}

func (context *Context) PublicKeyFromHex(str string) (pubkey *PublicKey) {
	bytes, _ := hex.DecodeString(str)
	_, pubkey, _ = EcPubkeyParse(context, bytes)
	return
}

/*func GetThreadId() uint32 {
	return uint32(C.getSelfThreadId())
}

func GetThreadId64() uint64 {
	return uint64(C.getSelfThreadId64())
}*/

/** Opaque data structure that holds rewriteable "scratch space"
 *
 *  The purpose of this structure is to replace dynamic memory allocations,
 *  because we target architectures where this may not be available. It is
 *  essentially a resizable (within specified parameters) block of bytes,
 *  which is initially created either by memory allocation or TODO as a pointer
 *  into some fixed rewritable space.
 *
 *  Unlike the context object, this cannot safely be shared between threads
 *  without additional synchronization logic.
 *
typedef struct secp256k1_scratch_space_struct secp256k1_scratch_space;
*/
type ScratchSpace = C.secp256k1_scratch_space

/** Create a secp256k1 scratch space object.
 *
 *  Returns: a newly created scratch space.
 *  Args: ctx:  an existing context object (cannot be NULL)
 *  In:   size: amount of memory to be available as scratch space. Some extra
 *              (<100 bytes) will be allocated for extra accounting.
 *
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT secp256k1_scratch_space* secp256k1_scratch_space_create(
	const secp256k1_context* ctx,
	size_t size
) SECP256K1_ARG_NONNULL(1);
*/
func ScratchSpaceCreate(
	ctx *Context,
	size int,
) (
	scratch *ScratchSpace,
	err error,
) {
	scratch = C.secp256k1_scratch_space_create(
		ctx.ctx,
		C.size_t(size),
	)
	if scratch == nil {
		err = errors.New("failed to create scratch space")
	}
	return
}

/** Destroy a secp256k1 scratch space.
 *
 *  The pointer may not be used afterwards.
 *  Args:       ctx: a secp256k1 context object.
 *          scratch: space to destroy
 *
SECP256K1_API void secp256k1_scratch_space_destroy(
	const secp256k1_context* ctx,
	secp256k1_scratch_space* scratch
) SECP256K1_ARG_NONNULL(1);
*/
func ScratchSpaceDestroy(
	ctx *Context,
	scratch *ScratchSpace,
) {
	C.secp256k1_scratch_space_destroy(
		ctx.ctx,
		scratch,
	)
}

/* Compute msghash = SHA256(combined_nonce, combined_pk, msg)
 *
static void secp256k1_musig_compute_messagehash(const secp256k1_context *ctx, unsigned char *msghash, const secp256k1_musig_session *session) {
**/
func musigComputeMessageHash(ctx *Context, session *MusigSession) (msghash [32]byte) {
	C.secp256k1_musig_compute_messagehash(ctx.ctx, cBuf(msghash[:]), session)
	return
}

/** SumBlindGeneratorBlind takes a value (64-bit int), and both
 *  value's and asset's blinding factors and computes using formula:
 *  r + (v * ra)
 *
 *   IN: v = value 64 bit int
 *       r = value's blinding factor
 *      ra = asset's blinding factor
 *   OUT:
 *        result: 32-byte scalar value
 *     err == nil if success
 */
func BlindValueGeneratorBlindSum(
	v uint64,
	ra []byte,
	r []byte,
) (
	result [32]byte,
	err error,
) {
	copy(result[:], r)
	if 1 != C.blind_value_generator_blind_sum(
		C.uint64_t(v),
		cBuf(ra),
		cBuf(result[:]),
	) {
		err = errors.New(ErrorCommitmentCommit)
	}
	return
}

/** Computes the sum of multiple positive and negative pedersen commitments
* Returns 1: sum successfully computed.
* In:     ctx:        pointer to a context object, initialized for Pedersen commitment (cannot be NULL)
*         commits:    pointer to array of pointers to the commitments. (cannot be NULL if pcnt is non-zero)
*         pcnt:       number of commitments pointed to by commits.
*         ncommits:   pointer to array of pointers to the negative commitments. (cannot be NULL if ncnt is non-zero)
*         ncnt:       number of commitments pointed to by ncommits.
*  Out:   commit_out: pointer to the commitment (cannot be NULL)
*
 */
func CommitSum(
	context *Context,
	poscommits []*Commitment,
	negcommits []*Commitment,
) (
	*Commitment,
	error,
) {
	posarr := makeCommitmentsArray(len(poscommits))
	defer freeCommitmentsArray(posarr)
	for pi, pc := range poscommits {
		setCommitmentsArray(posarr, pc, pi)
	}

	negarr := makeCommitmentsArray(len(negcommits))
	defer freeCommitmentsArray(negarr)
	for ni, nc := range negcommits {
		setCommitmentsArray(negarr, nc, ni)
	}

	var tmp Commitment
	if 1 != C.secp256k1_pedersen_commit_sum(
		context.ctx,
		&tmp,
		posarr, C.size_t(len(poscommits)),
		negarr, C.size_t(len(negcommits)),
	) {
		return nil, errors.New("error calculating sum of commitments")
	}
	/*SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_pedersen_commit_sum(
		const secp256k1_context* ctx,
		secp256k1_pedersen_commitment *commit_out,
		const secp256k1_pedersen_commitment * const* commits, size_t pcnt,
		const secp256k1_pedersen_commitment * const* ncommits, size_t ncnt
	) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5);*/
	return &tmp, nil
}

/** Converts a pedersent commit to a pubkey
 * In:  commit: pointer to a single commit
 * Out: pubkey: resulting pubkey
 */
func CommitmentToPublicKey(commit *Commitment) (*PublicKey, error) {
	pubkey := newPublicKey()
	if 1 != C.secp256k1_pedersen_commitment_to_pubkey(pubkey.pk, commit) {
		return nil, errors.New(ErrorCommitmentPubkey)
	}
	return pubkey, nil
}

func makeBytesArray(size int) **C.uchar {
	return C.makeBytesArray(C.int(size))
}

func setBytesArray(array **C.uchar, value *C.uchar, index int) {
	C.setBytesArray(array, value, C.int(index))
}

func getBytesArray(array **C.uchar, index int) *C.uchar {
	return C.getBytesArray(array, C.int(index))
}

func freeBytesArray(array **C.uchar) {
	C.freeBytesArray(array)
}
