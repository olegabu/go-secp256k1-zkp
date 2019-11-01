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
#include "include/secp256k1_schnorrsig.h"
static unsigned char** makeBytesArray(int size) { return !size ? NULL : calloc(sizeof(unsigned char*), size); }
static void setBytesArray(unsigned char** a, unsigned char* v, int i) { if(a) a[i] = v; }
static unsigned char* getBytesArray(unsigned char** a, int i) { return !a ? NULL : a[i]; }
static void freeBytesArray(unsigned char** a) { if(a) free(a); }
static secp256k1_schnorrsig** makeSchnorrsigArray(int size) { return !size ? NULL : calloc(sizeof(secp256k1_schnorrsig*), size); }
static void setSchnorrsigArray(secp256k1_schnorrsig** a, secp256k1_schnorrsig* v, int i) { if (a) a[i] = v; }
static void freeSchnorrsigArray(secp256k1_schnorrsig** a) { if(a) free(a); }
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
	c *C.secp256k1_schnorrsig
}

const (
	ErrorSchnorrsigSize      string = "Schnorr signature data expected length is 64 bytes"
	ErrorSchnorrsigParse     string = "Unable to parse the data as a Schnorr signature"
	ErrorSchnorrsigCount     string = "Number of elements differ in input arrays"
	ErrorSchnorrsigSerialize string = "Unable to serialize the data as a Schnorr signature"
	ErrorSchnorrsigSign      string = "Error creating Schnorr signature"
	ErrorSchnorrsigVerify    string = "Error verifying Schnorr signature"
)

func newSchnorrsig() *Schnorrsig {
	return &Schnorrsig{
		&C.secp256k1_schnorrsig{},
	}
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
func SchnorrsigParse(
	context *Context,
	data []byte,
) (
	schnorrsig *Schnorrsig,
	failure error,
) {
	schnorrsig = newSchnorrsig()
	if 1 != int(
		C.secp256k1_schnorrsig_parse(
			context.ctx,
			schnorrsig.c,
			cBuf(data))) {
		return nil, errors.New(ErrorSchnorrsigParse)
	}
	return schnorrsig, nil
}

/** Serialize Schnorr signature into byte sequence.
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:   ctx:        a secp256k1 context object.
 *  In:     Schnorrsig   a generator object
 *  Out:    status, data, error: 64-byte byte array
 */
func SchnorrsigSerialize(
	context *Context,
	schnorrsig *Schnorrsig,
) (
	[]byte, error,
) {
	var data [64]byte
	if 1 != int(
		C.secp256k1_schnorrsig_serialize(
			context.ctx,
			cBuf(data[:]),
			schnorrsig.c)) {
		return nil, errors.New(ErrorSchnorrsigSerialize)
	}
	return data[:], nil
}

/** Create a Schnorr signature
 *
 *  In:          ctx:  pointer to a context object
 *            hash32:  32-byte message hash being signed
 *	     	  seckey:  32-byte secret key
// TODO: *         noncefunc:  optional custom nonce generation function, the default one is secp256k1_nonce_function_bipschnorr
//       *         nonceseed:  optional seed data for the custom nonce generation function
 *
 *  Out:  schnorrsig:  pointer to resulting Schnorr signature
 *      noncenegated:  non-zero if signing algorithm negated the nonce
 *
 *  Returns:       1:  Success
 *                 0:  Failure
*/
func SchnorrsigSign(
	context *Context,
	hash32 [32]byte,
	seckey [32]byte,
	//	noncefunc *NonceGenerator,
	//	nonceseed []byte,
) (
	schnorrsig *Schnorrsig,
	noncenegated bool,
	err error,
) {
	schnorrsig = newSchnorrsig()
	var noncenegatedint C.int
	if 1 != int(
		C.secp256k1_schnorrsig_sign(
			context.ctx,
			schnorrsig.c,
			&noncenegatedint,
			cBuf(hash32[:]),
			cBuf(seckey[:]),
			nil,
			nil)) {
		return nil, false, errors.New(ErrorSchnorrsigSign)
	}
	noncenegated = 1 == int(noncenegatedint)
	return
}

/** Verify a Schnorr signature.
 *
 *  Returns: 1: correct signature
 *           0: incorrect or unparseable signature
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:      sig: the signature being verified (cannot be NULL)
 *         msg32: the 32-byte message hash being verified (cannot be NULL)
 *        pubkey: pointer to a public key to verify with (cannot be NULL)
 */
func SchnorrsigVerify(
	context *Context,
	schnorrsig *Schnorrsig,
	msg []byte,
	pubkey *PublicKey,
) (
	err error,
) {
	if 1 != int(
		C.secp256k1_schnorrsig_verify(
			context.ctx,
			schnorrsig.c,
			cBuf(msg),
			pubkey.pk)) {
		return errors.New(ErrorSchnorrsigVerify)
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
