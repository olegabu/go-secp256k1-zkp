/* This package implements Zero Knowledge Proof algorithms for Golang
** Contains Go bindings for the secp256k1-zkp C-library, which is
** based on the secp256k1 - a highly optimized implementation of the
** 256-bit elliptic curve used in Bitcoin blockchain.
 */
package secp256k1

/*
#cgo CFLAGS: -I${SRCDIR}/secp256k1-zkp -I${SRCDIR}/secp256k1-zkp/src
#include <stdlib.h>
#include "include/secp256k1_aggsig.h"
static secp256k1_pubkey** makePubkeyArray(int size) { return calloc(sizeof(secp256k1_pubkey*), size); }
static void setArrayPubkey(secp256k1_pubkey **a, secp256k1_pubkey *pubkey, int n) { a[n] = pubkey; }
static void freePubkeyArray(secp256k1_pubkey **a) { free(a); }
static secp256k1_aggsig_partial_signature** makePartsigArray(int size) { return calloc(sizeof(secp256k1_aggsig_partial_signature*), size); }
static void setArrayPartsig(secp256k1_aggsig_partial_signature **a, secp256k1_aggsig_partial_signature *partsig, int n) { a[n] = partsig; }
static void freePartsigArray(secp256k1_aggsig_partial_signature **a) { free(a); }
static unsigned char** makeBytesArray(int size) { return !size ? NULL : calloc(sizeof(unsigned char*), size); }
static void setBytesArray(unsigned char** a, unsigned char* v, int i) { if (a) a[i] = v; }
static unsigned char* getBytesArray(unsigned char** a, int i) { return !a ? NULL : a[i]; }
static void freeBytesArray(unsigned char** a) { if (a) free(a); }
typedef struct { unsigned char data[64]; } secp256k1_aggsig_signature;
*/
import "C"
import (
	"encoding/hex"
	"unsafe"
	"fmt"
)

const (
	ErrorAggsigSize          string = "Signature data expected length is 64 bytes"
	ErrorAggsigParse         string = "Unable to parse the data as a signature"
	ErrorAggsigCount         string = "Number of elements differ in input arrays"
	ErrorAggsigSign          string = "Unable to generate a signature"
	ErrorAggsigArgs          string = "Invalid arguments"
	ErrorAggsigVerify        string = "Signature verification failed"
	ErrorAggsigAddSigsSingle string = "Error calculating sum of signatures"
	ErrorAggsigContextCreate string = "Error creating an aggsig context object"
	ErrorAggsigGenNonce      string = "Error calling AggsigGenerateNonce"
	ErrorAggsigGenSecNonce   string = "Error calling AggsigGenerateSecureNonce"
)

/****************************************************************************************************************
**
**  Begin of AggsigContext section
 */

/** Opaque data structure that holds context for the aggregated signature state machine
 *
 *  During execution of an aggregated signature this context object will contain secret
 *  data. It MUST be destroyed by `secp256k1_aggsig_context_destroy` to erase this data
 *  before freeing it. Context objects are sized based on the number of signatures to
 *  aggregate, and can be reused for multiple signature runs, provided that each run
 *  aggregates the same number of signatures.
 *
 *  Destroying and recreating a context object is essentially just deallocating and
 *  reallocating memory, there is no expensive precomputation as there is with the general
 *  libsecp256k1 context.
 *
 *  Once a context object is created with `secp256k1_aggsig_context_create` the workflow
 *  is as follows.
 *
 *      1. For each index controlled by the user, use `secp256k1_aggsig_generate_nonce`
 *         to generate a public/private nonce pair for that index. [TODO export the
 *         public nonce for other users]
 *      2. [TODO import others' public nonces]
 *      3. For each index controlled by the user, use `secp256k1_aggsig_partial_sign`
 *         to generate a partial signature that should be distributed to all peers.
 */
// typedef struct secp256k1_aggsig_context_struct secp256k1_aggsig_context;
type AggsigContext struct {
	ctx *C.secp256k1_aggsig_context
}

// Create empty AggsigContext object
func newAggsigContext() *AggsigContext {
	return &AggsigContext{
		ctx: &C.secp256k1_aggsig_context{}}
}

/** Create an aggregated signature context object with a given size
 *
 *  Returns: a newly created context object.
 *  Args:       ctx:  an existing context object (cannot be NULL)
 *  In:     pubkeys: public keys for each signature (cannot be NULL)
 *        n_pubkeys: number of public keys/signatures to aggregate
 *             seed: a 32-byte seed to use for the nonce-generating RNG (cannot be NULL)
 */
// SECP256K1_API secp256k1_aggsig_context* secp256k1_aggsig_context_create(
//     const secp256k1_context *ctx,
//     const secp256k1_pubkey *pubkeys,
//     size_t n_pubkeys,
//     const unsigned char *seed
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_WARN_UNUSED_RESULT;
func AggsigContextCreate(
	context *Context,
	pubkeys []*PublicKey,
	seed32 []byte,
) (
	*AggsigContext,
	error,
) {
	cpubkeys := C.makePubkeyArray(C.int(len(pubkeys)))
	for index, pubkey := range pubkeys {
		C.setArrayPubkey(cpubkeys, pubkey.pk, C.int(index))
	}
	defer C.freePubkeyArray(cpubkeys)

	aggsigctx := newAggsigContext()
	aggsigctx.ctx = C.secp256k1_aggsig_context_create(
		context.ctx,
		*cpubkeys,
		C.size_t(len(pubkeys)),
		cBuf(seed32),
	)
	if aggsigctx.ctx == nil {
		return nil, fmt.Errorf(ErrorAggsigContextCreate)
	}

	return aggsigctx, nil
}

/** Destroy an aggregated signature context object. If passed NULL, is a no-op.
 *
 *  Args: sigctx:  an existing context object
 */
// SECP256K1_API void secp256k1_aggsig_context_destroy(
//     secp256k1_aggsig_context *sigctx
// );
// Destructor of ScratchSpace object
func AggsigContextDestroy(sigctx *AggsigContext) {
	if sigctx != nil {
		C.secp256k1_aggsig_context_destroy(sigctx.ctx)
	}
}

/* End of AggsigContext section
*********************************************/

/** Generate a nonce pair for a single signature part in an aggregated signature
 *
 *  Returns: 1 on success
 *           0 if a nonce has already been generated for this index
 *  Args:    ctx: an existing context object, initialized for signing (cannot be NULL)
 *        aggctx: an aggsig context object (cannot be NULL)
 *  In:    index: which signature to generate a nonce for
 */
// SECP256K1_API int secp256k1_aggsig_generate_nonce(
//     const secp256k1_context* ctx,
//     secp256k1_aggsig_context* aggctx,
//     size_t index
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_WARN_UNUSED_RESULT;
func AggsigGenerateNonce(
	context *Context,
	aggsigcontext *AggsigContext,
	sigindex uint,
) error {
	if 1 != C.secp256k1_aggsig_generate_nonce(
		context.ctx,
		aggsigcontext.ctx,
		C.size_t(sigindex)) {

		return fmt.Errorf(ErrorAggsigGenNonce)
	}
	return nil
}

/** Generates and exports a secure nonce, of which the public part can be shared
 *  and fed back for a later signature
 *
 *  Returns: 1 on success
 *  Args:    ctx: an existing context object, initialized for signing (cannot be NULL)
 *  In:    seed: A random seed value
 *  Out:   secnonce32: The secure nonce (scalar), guaranteed to be Jacobi 1
 */
// extern SECP256K1_API int secp256k1_aggsig_export_secnonce_single(
//     const secp256k1_context* ctx,
//     unsigned char* secnonce32,
//     const unsigned char* seed
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_WARN_UNUSED_RESULT;
func AggsigGenerateSecureNonce(
	context *Context,
	seed32 []byte,
) (
	secnonce32 [32]byte,
	err error,
) {
	if seed32 == nil {
		seed := Random256()
		seed32 = seed[:]
	}
	if 1 != C.secp256k1_aggsig_export_secnonce_single(
		context.ctx,
		cBuf(secnonce32[:]),
		cBuf(seed32)) {

		err = fmt.Errorf(ErrorAggsigGenSecNonce)
	}

	// sec, err := hex.DecodeString("0A00000000000000000000000000000000000000000000000000000000000000")
	// copy(secnonce32[:], sec[:])

	return
}

/** Opaque data structure that holds a partial signature
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied, moved.
 *  and transmitted as raw bytes.
 */
// typedef struct {
//     unsigned char data[32];
// } secp256k1_aggsig_partial_signature;
type AggsigSignature [64]C.uchar

type AggsigSignaturePartial [64]C.uchar
type AggsigSignaturePartialPtr []C.uchar

func newAggsigSignature() *AggsigSignature {
	return &AggsigSignature{}
}

func newAggsigSignaturePartial() *AggsigSignaturePartial {
	return &AggsigSignaturePartial{}
}

func AggsigSignaturePartialParse(data []byte) (sig AggsigSignaturePartial, err error) {
	if len(data) != 64 {
		err = fmt.Errorf("Can't parse a partial signature, invalid length")
	} else {
		for i, b := range data {
			sig[i] = C.uchar(b)
		}
	}

	return
}

func AggsigSignaturePartialSerialize(sig *AggsigSignaturePartial) (data [64]byte) {
	if sig != nil {
		for i, b := range *sig {
			data[i] = byte(b)
		}
	}
	return
}

/** Opaque data structure that holds a full signature
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied, moved.
 *  and transmitted as raw bytes.
 */
// typedef struct {
//     unsigned char data[32];
// } secp256k1_aggsig_partial_signature;
type AggsigPartialSignature struct {
	sig *C.secp256k1_aggsig_partial_signature
}

func newAggsigPartialSignature() *AggsigPartialSignature {
	return &AggsigPartialSignature{
		sig: &C.secp256k1_aggsig_partial_signature{},
	}
}

/** Parse sequence of bytes as a aggsig object.
 *  In:   ctx:     a secp256k1 context object.
 *        data:    64-byte serialized data
 *  Out: *Aggrsig, error
 */
func AggsigSignatureParse(
	ctx *Context,
	data []byte,
) (
	sig *AggsigSignature,
	err error,
) {
	if len(data) != LenCompactSig {
		return nil, fmt.Errorf(ErrorCompactSigSize)
	}

	sig = newAggsigSignature()
	if 1 != C.secp256k1_ecdsa_signature_parse_compact(
		ctx.ctx,
		(*C.secp256k1_ecdsa_signature)(unsafe.Pointer(&sig[0])),
		(*C.uchar)(unsafe.Pointer(&data[0]))) {

		return nil, fmt.Errorf(ErrorCompactSigParse)
	}

	return
}

/* Serialize an aggsig signature in compact (64 byte) format.
 *  In:   ctx   secp256k1 context object
 *        sig   aggsig signature object
 *  Out:  data  serialized data bytes
 */
func AggsigSignatureSerialize(
	ctx *Context,
	sig *AggsigSignature,
) (
	raw [64]byte,
) {
	C.secp256k1_ecdsa_signature_serialize_compact(
		ctx.ctx,
		(*C.uchar)(unsafe.Pointer(&raw[0])),
		(*C.secp256k1_ecdsa_signature)(unsafe.Pointer(&sig[0])))

	return
}

func (aggsig *AggsigSignature) Bytes(context *Context) (bytes [64]byte) {
	bytes = AggsigSignatureSerialize(context, aggsig)
	return
}

func (aggsig *AggsigSignature) Hex(context *Context) string {
	bytes := aggsig.Bytes(context)
	return hex.EncodeToString(bytes[:])
}

func (context *Context) AggsigUnhex(str string) (sig *AggsigSignature, err error) {
	var bytes []byte
	bytes, err = hex.DecodeString(str)
	if err != nil {
		return
	}
	sig, err = AggsigSignatureParse(context, bytes)
	return
}

func (context *Context) AggsigUnhexNE(str string) *AggsigSignature {
	sig, err := context.AggsigUnhex(str)
	if err != nil {
		return nil
	}
	return sig
}

/** Generate a single-signer signature (or partial sig), without a stored context
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:    ctx: an existing context object, initialized for signing (cannot be NULL)
 *  Out:     sig64: the completed signature (cannot be NULL)
 *  In:      msg32: the message to sign (cannot be NULL)
 *           seckey32: the secret signing key (cannot be NULL)
 *           secnonce32: secret nonce to use. If NULL, a nonce will be generated
 *           extra32: if non-NULL, add this key to s
 *           pubnonce_for_e: If this is non-NULL, encode this value in e instead of the derived
 *           pubnonce_total: If non-NULL, allow this signature to be included in combined sig
 *               in all cases by negating secnonce32 if the public nonce total has jacobi symbol
 *               -1. secnonce32 must also be provided
 *           pubkey_for_e: If this is non-NULL, encode this value in e
 *           seed: a 32-byte seed to use for the nonce-generating RNG (cannot be NULL)
 */
// SECP256K1_API int secp256k1_aggsig_sign_single(
//     const secp256k1_context* ctx,
//     unsigned char *sig64,
//     const unsigned char *msg32,
//     const unsigned char *seckey32,
//     const unsigned char* secnonce32,
//     const unsigned char* extra32,
//     const secp256k1_pubkey *pubnonce_for_e,
//     const secp256k1_pubkey* pubnonce_total,
//     const secp256k1_pubkey* pubkey_for_e,
//     const unsigned char* seed)
// SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(10) SECP256K1_WARN_UNUSED_RESULT;
func AggsigSignSingle(
	context *Context,
	msg32 []byte,
	secBlind []byte,
	secNonce []byte,
	extra32 []byte,
	pubNonce *PublicKey,
	pubNonceSum *PublicKey,
	pubBlind *PublicKey,
	seed32 []byte,
) (
	sig AggsigSignature,
	err error,
) {
	if seed32 == nil {
		seed := Random256()
		seed32 = seed[:]
	}

	if 1 != C.secp256k1_aggsig_sign_single(
		context.ctx,
		&sig[0],
		cBuf(msg32),
		cBuf(secBlind),
		cBuf(secNonce),
		cBuf(extra32),
		pk(pubNonce),
		pk(pubNonceSum),
		pk(pubBlind),
		cBuf(seed32)) {

		err = fmt.Errorf(ErrorAggsigSign)
	}
	return
}

/** Generate a single signature part in an aggregated signature
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:    ctx: an existing context object, initialized for signing (cannot be NULL)
 *        aggctx: an aggsig context object (cannot be NULL)
 *  Out:   partial: the generated signature part (cannot be NULL)
 *  In:  msg32: the message to sign (cannot be NULL)
 *        seckey32: the secret signing key (cannot be NULL)
 *           index: the index of this signature in the aggregate signature
 */
// SECP256K1_API int secp256k1_aggsig_partial_sign(
//     const secp256k1_context* ctx,
//     secp256k1_aggsig_context* aggctx,
//     secp256k1_aggsig_partial_signature *partial,
//     const unsigned char *msg32,
//     const unsigned char *seckey32,
//     size_t index
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_WARN_UNUSED_RESULT;
func AggsigPartialSign(
	context *Context,
	aggsigcontext *AggsigContext,
	msg32 []byte,
	seckey32 []byte,
	index uint,
) (
	partsig *AggsigPartialSignature,
	err error,
) {
	partsig = newAggsigPartialSignature()
	if 1 != C.secp256k1_aggsig_partial_sign(
		context.ctx,
		aggsigcontext.ctx,
		partsig.sig,
		cBuf(msg32),
		cBuf(seckey32),
		C.size_t(index)) {

		err = fmt.Errorf(ErrorAggsigSign)
	}
	return
}

/** Aggregate multiple signature parts into a single aggregated signature
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:    ctx: an existing context object, initialized for signing (cannot be NULL)
 *        aggctx: an aggsig context object (cannot be NULL)
 *  Out:     sig64: the completed signature (cannot be NULL)
 *  In:    partial: an array of partial signatures to aggregate (cannot be NULL)
 *          n_sigs: the number of partial signatures provided
 */
// SECP256K1_API int secp256k1_aggsig_combine_signatures(
//     const secp256k1_context* ctx,
//     secp256k1_aggsig_context* aggctx,
//     unsigned char *sig64,
//     const secp256k1_aggsig_partial_signature *partial,
//     size_t n_sigs
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_WARN_UNUSED_RESULT;
func AggsigCombineSignatures(
	context *Context,
	aggctx *AggsigContext,
	partsigs []*AggsigPartialSignature,
) (
	sig [64]byte,
	err error,
) {
	cpartsigs := C.makePartsigArray(C.int(len(partsigs)))
	for index, partsig := range partsigs {
		C.setArrayPartsig(cpartsigs, partsig.sig, C.int(index))
	}
	defer C.freePartsigArray(cpartsigs)

	if 1 != C.secp256k1_aggsig_combine_signatures(
		context.ctx,
		aggctx.ctx,
		cBuf(sig[:]),
		*cpartsigs,
		C.size_t(len(partsigs))) {

		err = fmt.Errorf(ErrorAggsigContextCreate)
	}

	return
}

/** Simple addition of two signatures + two public nonces into a single signature
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:    ctx: an existing context object, initialized for signing (cannot be NULL)
 *  Out:     sig64: the completed signature (s1+s2,n1+n2) (cannot be NULL)
 *  In:     sig1_64: a signature (from which s1 will2be taken)
 *          sig2_64: another signature (from which s1 will be taken)
 *          pubnonce_total: the total of all public nonces, will simple become R (negated if needed)
 */
// SECP256K1_API int secp256k1_aggsig_add_signatures_single(
//     const secp256k1_context* ctx,
//     unsigned char *sig64,
//     const unsigned char** sigs,
//     size_t num_sigs,
//     const secp256k1_pubkey* pubnonce_total
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_WARN_UNUSED_RESULT;
func AggsigAddSignaturesSingle(
	context *Context,
	sigs []*AggsigSignaturePartial,
	pubnoncetotal *PublicKey,
) (
	sig AggsigSignature,
	err error,
) {
	count := len(sigs)
	csigs := C.makeBytesArray(C.int(count))
	defer C.freeBytesArray(csigs)
	for i, s := range sigs {
		C.setBytesArray(csigs, &s[0], C.int(i))
	}

	// output := make([]C.uchar, 64)
	if 1 != C.secp256k1_aggsig_add_signatures_single(
		context.ctx,
		&sig[0],
		csigs,
		C.size_t(count),
		pk(pubnoncetotal)) {

		err = fmt.Errorf(ErrorAggsigAddSigsSingle)
	}

	return
	// return goBytes(output, 64), nil
}

/** Verify a single-signer signature, without a stored context
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:    ctx: an existing context object, initialized for signing (cannot be NULL)
 *  In:      sig64: signature (cannot be NULL)
 *           msg32: the message to verify (cannot be NULL)
 *           pubnonce: if non-NULL, override the public nonce used to calculate e
 *           pubkey: the public key (cannot be NULL)
 *           pubkey_total: if non-NULL, encode this value in e
 *           extra_pubkey: if non-NULL, subtract this pubkey from sG
 *           is_partial: whether to ignore the jacobi symbol of the combined R, set this to 1
 *               to verify partial signatures that may have had their secret nonces negated
 */
// SECP256K1_API int secp256k1_aggsig_verify_single(
//     const secp256k1_context* ctx,
//     const unsigned char *sig64,
//     const unsigned char *msg32,
//     const secp256k1_pubkey *pubnonce,
//     const secp256k1_pubkey *pubkey,
//     const secp256k1_pubkey *pubkey_total,
//     const secp256k1_pubkey *extra_pubkey,
//     const int is_partial)
// SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_WARN_UNUSED_RESULT;
func AggsigVerifySingle(
	ctx *Context,
	sig *AggsigSignature,
	msg []byte,
	pubNonce *PublicKey,
	pubBlind *PublicKey,
	pubBlindSum *PublicKey,
	pubExtra *PublicKey,
	isPartial bool,
) error {
	if 1 != C.secp256k1_aggsig_verify_single(
		ctx.ctx,
		&sig[0],
		cBuf(msg),
		pk(pubNonce),
		pk(pubBlind),
		pk(pubBlindSum),
		pk(pubExtra),
		bc(isPartial)) {

		return fmt.Errorf(ErrorAggsigVerify)
	}

	return nil
}

/** Verify an aggregate signature
 *
 *  Returns: 1 if the signature is valid, 0 if not
 *  Args:    ctx: an existing context object (cannot be NULL)
 *       scratch: a scratch space (cannot be NULL)
 *  In:    sig64: the signature to verify (cannot be NULL)
 *         msg32: the message that should be signed (cannot be NULL)
 *       pubkeys: array of public keys (cannot be NULL)
 *        n_keys: the number of public keys
 */
// SECP256K1_API int secp256k1_aggsig_verify(
//     const secp256k1_context* ctx,
//     secp256k1_scratch_space* scratch,
//     const unsigned char *sig64,
//     const unsigned char *msg32,
//     const secp256k1_pubkey *pubkeys,
//     size_t n_pubkeys
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_WARN_UNUSED_RESULT;
func AggsigVerify(
	context *Context,
	scratch *ScratchSpace,
	sig64 []byte,
	msg32 []byte,
	pubkeys []*PublicKey,
) error {
	count := len(pubkeys)
	cpubkeys := C.makePubkeyArray(C.int(count))
	for idx, key := range pubkeys {
		C.setArrayPubkey(cpubkeys, key.pk, C.int(idx))
	}
	defer C.freePubkeyArray(cpubkeys)
	if scratch != nil {

		if 1 != C.secp256k1_aggsig_verify(
			context.ctx,
			scratch.scr,
			cBuf(sig64),
			cBuf(msg32),
			*cpubkeys,
			C.size_t(count)) {

			return fmt.Errorf(ErrorAggsigVerify)
		}
	} else {

		if 1 != C.secp256k1_aggsig_build_scratch_and_verify(
			context.ctx,
			cBuf(sig64),
			cBuf(msg32),
			*cpubkeys,
			C.size_t(count)) {

			return fmt.Errorf(ErrorAggsigVerify)
		}
	}
	return nil
}

/** Verify an aggregate signature, building scratch space interally beforehand
 *
 *  Returns: 1 if the signature is valid, 0 if not
 *  Args:    ctx: an existing context object (cannot be NULL)
 *  In:    sig64: the signature to verify (cannot be NULL)
 *         msg32: the message that should be signed (cannot be NULL)
 *       pubkeys: array of public keys (cannot be NULL)
 *        n_keys: the number of public keys
 */
// extern SECP256K1_API int secp256k1_aggsig_build_scratch_and_verify(
//    const secp256k1_context* ctx,
//    const unsigned char *sig64,
//    const unsigned char *msg32,
//    const secp256k1_pubkey *pubkeys,
//    size_t n_pubkeys
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_WARN_UNUSED_RESULT;
func AggsigSignPartial(
	context *Context,
	secBlind []byte,
	secNonce []byte,
	pubNonceSum *PublicKey,
	pubBlindSum *PublicKey,
	msg []byte,
) (
	sig AggsigSignaturePartial,
	err error,
) {
	// Calculate signature using message M=fee, nonce in e=nonce_sum
	seed := Random256()
	if 1 != C.secp256k1_aggsig_sign_single(
		context.ctx,
		&sig[0],
		cBuf(msg),
		cBuf(secBlind),
		cBuf(secNonce),
		nil,
		pk(pubNonceSum),
		pk(pubNonceSum),
		pk(pubBlindSum),
		cBuf(seed[:])) {

		err = fmt.Errorf(ErrorAggsigSign)
	}
	return
}

func AggsigVerifyPartial(
	context *Context,
	sig *AggsigSignaturePartial,
	pubNonceSum *PublicKey,
	pubBlind *PublicKey,
	pubBlindSum *PublicKey,
	msg []byte,
) (
	err error,
) {

	if 1 != C.secp256k1_aggsig_verify_single(
		context.ctx,
		&sig[0],
		cBuf(msg),
		pk(pubNonceSum),
		pk(pubBlind),
		pk(pubBlindSum),
		nil,
		1) {

		err = fmt.Errorf(ErrorAggsigVerify)
	}
	return
}

func pk(key *PublicKey) *C.secp256k1_pubkey {
	if key == nil {
		return nil
	}
	return key.pk
}

func bc(val bool) C.int {
	if val {
		return C.int(1)
	}
	return C.int(0)
}
