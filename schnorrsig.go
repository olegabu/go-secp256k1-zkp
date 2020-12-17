/* This package implements Zero Knowledge Proof algorithms for Golang
**
** Contains Go bindings for the secp256k1-zkp C-library, which is
** based on the secp256k1 - a highly optimized implementation of the
** 256-bit elliptic curve used in Bitcoin blockchain.
 */

/** This module implements a variant of Schnorr signatures compliant with
 * (https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki).
 */
package secp256k1

/*
#include <stdlib.h>
#include <string.h>
#include "include/secp256k1_schnorrsig.h"
static unsigned char** makeBytesArray(int size) { return !size ? NULL : calloc(sizeof(unsigned char*), size); }
static void setBytesArray(unsigned char** a, unsigned char* v, int i) { if(a) a[i] = v; }
static unsigned char* getBytesArray(unsigned char** a, int i) { return !a ? NULL : a[i]; }
static void freeBytesArray(unsigned char** a) { if(a) free(a); }
static secp256k1_pubkey** makePubkeyArray(int size) { return !size ? NULL : calloc(sizeof(secp256k1_pubkey*), size); }
static void setPubkeyArray(secp256k1_pubkey **a, secp256k1_pubkey *pubkey, int n) { if (a) a[n] = pubkey; }
static void freePubkeyArray(secp256k1_pubkey **a) { if (a) free(a); }
*/
//#cgo CFLAGS: -I${SRCDIR}/secp256k1-zkp -I${SRCDIR}/secp256k1-zkp/src
import "C"
import (
	"errors"
)

/** Pointer to opaque data structure that holds a parsed Schnorr signature.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use the `secp256k1_schnorrsig_serialize` and
 *  `secp256k1_schnorrsig_parse` functions.
 */
type Schnorrsig struct {
	data [64]byte
}

const (
	ErrorSchnorrsigSize      string = "schnorr signature data expected length is 64 bytes"
	ErrorSchnorrsigParse     string = "unable to parse the data as a Schnorr signature"
	ErrorSchnorrsigCount     string = "number of elements differ in input arrays"
	ErrorSchnorrsigSerialize string = "unable to serialize the data as a Schnorr signature"
	ErrorSchnorrsigSign      string = "error creating Schnorr signature"
	ErrorSchnorrsigVerify    string = "error verifying Schnorr signature"
)

func newSchnorrsig(data []byte) *Schnorrsig {
	var sig Schnorrsig
	if len(data) == 64 {
		copy(sig.data[:], data)
	}
	return &sig
}

/** Parse sequence of bytes as a schnorrsig object.
 *
 *  Returns: 1 if input contains a valid schnorr signature
 *  Args: ctx:     a secp256k1 context object.
 *  In:   data:    64-byte serialized data
 *  Out:  status, *Schnorrsig, error
 *
 *  The signature is serialized in the form R||s, where R is a 32-byte public
 *  key (x-coordinate only; the y-coordinate is considered to be the unique
 *  y-coordinate satisfying the curve equation that is a quadratic residue)
 *  and s is a 32-byte big-endian scalar.
 *
 *  After the call, sig will always be initialized. If parsing failed or the
 *  encoded numbers are out of range, signature validation with it is
 *  guaranteed to fail for every message and public key.
 */
func SchnorrsigParse(data []byte) *Schnorrsig {
	schnorrsig := newSchnorrsig(data)

	return schnorrsig
}

/** Serialize Schnorr signature into byte sequence.
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:   ctx:        a secp256k1 context object.
 *  In:     Schnorrsig   a Schnorr signature object
 *  Out:    status, data, error: 64-byte byte array
 */
func SchnorrsigSerialize(schnorrsig *Schnorrsig) []byte {
	var bytes [64]byte
	copy(bytes[:], schnorrsig.data[:])
	return bytes[:]
}

/** Create a Schnorr signature.
 *
 *  Does _not_ strictly follow BIP-340 because it does not verify the resulting
 *  signature. Instead, you can manually use secp256k1_schnorrsig_verify and
 *  abort if it fails.
 *
 *  Otherwise BIP-340 compliant if the noncefp argument is NULL or
 *  secp256k1_nonce_function_bip340 and the ndata argument is 32-byte auxiliary
 *  randomness.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:   sig64: pointer to a 64-byte array to store the serialized signature (cannot be NULL)
 *  In:    msg32: the 32-byte message being signed (cannot be NULL)
 *       keypair: pointer to an initialized keypair (cannot be NULL)
 *       noncefp: pointer to a nonce generation function. If NULL, secp256k1_nonce_function_bip340 is used
 *         ndata: pointer to arbitrary data used by the nonce generation
 *                function (can be NULL). If it is non-NULL and
 *                secp256k1_nonce_function_bip340 is used, then ndata must be a
 *                pointer to 32-byte auxiliary randomness as per BIP-340.
 *
SECP256K1_API int secp256k1_schnorrsig_sign(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_keypair *keypair,
    secp256k1_nonce_function_hardened noncefp,
    void *ndata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);
*/
func SchnorrsigSign(
	context *Context,
	msg32 []byte,
	keypair *Keypair,
) (
	schnorrsig *Schnorrsig,
	err error,
) {
	schnorrsig = newSchnorrsig(nil)
	if 1 != int(C.secp256k1_schnorrsig_sign(
		context.ctx,
		cBuf(schnorrsig.data[:]),
		cBuf(msg32),
		keypair,
		nil,
		nil,
	)) {
		err = errors.New(ErrorSchnorrsigSign)
	}

	return
}

/** Verify a Schnorr signature.
 *
 *  Returns: 1: correct signature
 *           0: incorrect signature
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:    sig64: pointer to the 64-byte signature to verify (cannot be NULL)
 *         msg32: the 32-byte message being verified (cannot be NULL)
 *        pubkey: pointer to an x-only public key to verify with (cannot be NULL)
 *
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_verify(
    const secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);
*/
func SchnorrsigVerify(
	context *Context,
	schnorrsig *Schnorrsig,
	msg32 []byte,
	pubkey *XonlyPubkey,
) (
	err error,
) {
	if 1 != C.secp256k1_schnorrsig_verify(
		context.ctx,
		cBuf(schnorrsig.data[:]),
		cBuf(msg32),
		pubkey) {

		err = errors.New(ErrorSchnorrsigVerify)
	}
	return
}

/** Verifies a set of Schnorr signatures.
 *
 * Returns 1 if all succeeded, 0 otherwise. In particular, returns 1 if n_sigs is 0.
 *
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *       scratch: scratch space used for the multiexponentiation
 *  In:      sig: array of signatures, or NULL if there are no signatures
 *         msg32: array of messages, or NULL if there are no signatures
 *            pk: array of public keys, or NULL if there are no signatures
 *        n_sigs: number of signatures in above arrays. Must be smaller than
 *                2^31 and smaller than half the maximum size_t value. Must be 0
 *                if above arrays are NULL.
 */
/*
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_verify_batch(
        const secp256k1_context* ctx,
        secp256k1_scratch_space* scratch,
        const secp256k1_schnorrsig* const* sig,
        const unsigned char* const* msg32,
        const secp256k1_pubkey* const* pk,
        size_t n_sigs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);
*/
/* TODO
func SchnorrsigVerifyBatch(
	context *Context,
	scratch *ScratchSpace,
	sig []*Schnorrsig,
	data [][32]byte,
	pubkey []*PublicKey,
) (
	err error,
) {
	sl := len(sig)
	dl := len(data)
	kl := len(pubkey)
	if sl != dl || sl != kl {
		return errors.New(ErrorSchnorrsigCount)
	}
	ss := C.makeSchnorrsigArray(C.int(sl))
	ds := C.makeBytesArray(C.int(sl))
	ks := C.makePubkeyArray(C.int(sl))
	for i := 0; i < sl; i++ {
		C.setSchnorrsigArray(ss, sig[i].c, C.int(i))
		C.setBytesArray(ds, cBuf(data[i][:]), C.int(i))
		C.setPubkeyArray(ks, pubkey[i].pk, C.int(i))
	}
	defer C.freeSchnorrsigArray(ss)
	defer C.freeBytesArray(ds)
	defer C.freePubkeyArray(ks)

	if 1 != int(
		C.secp256k1_schnorrsig_verify_batch(
			context.ctx,
			scratch.scr,
			ss,
			ds,
			ks,
			C.size_t(sl))) {
		return errors.New(ErrorSchnorrsigVerify)
	}
	return
}
*/
