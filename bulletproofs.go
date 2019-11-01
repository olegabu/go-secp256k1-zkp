/** This package implements Zero Knowledge Proof algorithms for Golang
**
** Contains Go bindings for the secp256k1-zkp C-library, which is
** based on the secp256k1 - a highly optimized implementation of the
** 256-bit elliptic curve used in Bitcoin blockchain.
**/
package secp256k1

/*
#cgo CFLAGS: -I${SRCDIR}/secp256k1-zkp -I${SRCDIR}/secp256k1-zkp/src
#include <stdlib.h>
#include "include/secp256k1_bulletproofs.h"
static secp256k1_pedersen_commitment** makeCommitmentsArray(int size) {
	return calloc(sizeof(secp256k1_pedersen_commitment*), size);
}
static void setCommitmentsArray(secp256k1_pedersen_commitment** a, secp256k1_pedersen_commitment* v, int i) {
	a[i] = v;
}
static void freeCommitmentsArray(secp256k1_pedersen_commitment** a) {
	free(a);
}
static size_t* makeSizeArray(int size) {
	return calloc(sizeof(size_t), size);
}
static void setSizeArray(size_t* a, size_t v, int i) {
	a[i] = v;
}
static void freeSizeArray(size_t* a) {
	free(a);
}
static unsigned char** makeByteArray(int size) {
	return calloc(sizeof(unsigned char*), size);
}
static void setByteArray(unsigned char** a, unsigned char* v, int i) {
	a[i] = v;
}
static unsigned char* getByteArray(unsigned char** a, int i) {
	return a[i];
}
static void freeByteArray(unsigned char** a) {
	free(a);
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

/** Pointer to opaque data structure that stores a base point
 *
 *      The exact representation of data inside is implementation defined and not
 *      guaranteed to be portable between different platforms or versions. It is
 *      however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *      If you need to convert to a format suitable for storage, transmission, or
 *      comparison, use secp256k1_generator_serialize and secp256k1_generator_parse.
 */
type BulletproofGenerators struct {
	gens *C.secp256k1_bulletproof_generators
}

const (
	/* Maximum depth of 31 lets us validate an aggregate of 2^25 64-bit proofs */
	BulletproofMaxDepth = int(C.SECP256K1_BULLETPROOF_MAX_DEPTH) // = 31

	/* Size of a hypothetical 31-depth rangeproof, in bytes */
	BulletproofMaxProof = int(C.SECP256K1_BULLETPROOF_MAX_PROOF) // = 160 + 36*32 + 7

	/* Error types */
	ErrorBulletproofCount               string = "Number of elements differ in input arrays"
	ErrorBulletproofKeySize             string = "Generator input data length should be 33 bytes"
	ErrorBulletproofGenerationFailure   string = "Unable to parse this data as a generator"
	ErrorBulletproofVerificationFailure string = "Unable to parse this data as a generator"
)

/**********************************************************
**  Begin of ScratchSpace memorysection
 */

// ScratchSpace reserves temporary memory block for
// elliptic curve crypto operations.
type ScratchSpace struct {
	scr *C.secp256k1_scratch_space
}

// Create empty Scratch object
func newScratchSpace() *ScratchSpace {
	return &ScratchSpace{
		scr: &C.secp256k1_scratch_space{},
	}
}

// Attempts to allocate a new stack frame with `n` available bytes. Returns 1 on success, 0 on failure
// Returns a pointer into the most recently allocated frame, or NULL if there is insufficient available space
func ScratchSpaceCreate(context *Context, max_size uint64) (*ScratchSpace, error) {
	scratch := newScratchSpace()
	scratch.scr = C.secp256k1_scratch_space_create(
		context.ctx,
		C.size_t(max_size))
	return scratch, nil
}

// Destructor of ScratchSpace object
func ScratchSpaceDestroy(scratch *ScratchSpace) {
	C.secp256k1_scratch_space_destroy(scratch.scr)
}

/*
    End of ScratchSpace section             **
*********************************************/

/*********************************************
**  Begin of BulletproofGenerators section
 */

/** Allocates and initializes a list of NUMS generators, along with precomputation data,
 *  returns a list of generators, or NULL if allocation failed.
 *      context:        pointer to a context object (cannot be NULL)
 *      blinding_gen:   generator that blinding factors will be multiplied by (cannot be NULL)
 *      num:            number of NUMS generators to produce
 */
func BulletproofGeneratorsCreate(
	context *Context,
	blinding_gen *Generator,
	num uint64,
) *BulletproofGenerators {
	return &BulletproofGenerators{
		gens: C.secp256k1_bulletproof_generators_create(
			context.ctx,
			blinding_gen.gen,
			C.size_t(num))}
}

/** Destroys a list of NUMS generators, freeing allocated memory
 *
 *      context:        pointer to a context object (cannot be NULL)
 *      generator:      pointer to the generator set to be destroyed
 */
func BulletproofGeneratorsDestroy(context *Context, generators *BulletproofGenerators) {
	C.secp256k1_bulletproof_generators_destroy(
		context.ctx,
		generators.gens)
}

/*
    End of BulletproofGenerators section      **
***********************************************/

/**********************************************
**  Begin of Bulletproof functions section
 */

/** Verifies a single bulletproof (aggregate) rangeproof
 *      Inputs:
 *                context: pointer to a context object initialized for verification (cannot be NULL)
 *                scratch: scratch space with enough memory for verification (cannot be NULL)
 *                   gens: generator set with at least 2*nbits*n_commits many generators (cannot be NULL)
 *                  proof: byte-serialized rangeproof (cannot be NULL)
 *                   plen: length of the proof
 *              min_value: array of minimum values to prove ranges above, or NULL for all-zeroes
 *                 commit: array of pedersen commitment that this rangeproof is over (cannot be NULL)
 *              n_commits: number of commitments in the above array (cannot be 0)
 *                  nbits: number of bits proven for each range
 *              value_gen: generator multiplied by value in pedersen commitments (cannot be NULL)
 *           extra_commit: additonal data committed to by the rangeproof (may be NULL if `extra_commit_len` is 0)
 *       extra_commit_len: length of additional data
 *      Returns:
 *             true: rangeproof was valid
 *            false: rangeproof was invalid, or out of memory
 */
func BulletproofRangeproofVerify(
	context *Context,
	scratch *ScratchSpace,
	generators *BulletproofGenerators,
	proof []byte,
	minvalue []uint64,
	commit *Commitment,
	nbits int,
	valuegen *Generator,
	extracommit []byte,
) (
	int, error,
) {
	//comcnt := len(commit)
	//valcnt := len(minvalue)
	//if comcnt != valcnt {
	//	return 0, errors.New(ErrorBulletproofCount)
	//}
	//comms := C.makeCommitmentsArray(C.int(comcnt))
	//for i := 0; i < comcnt; i++ {
	//	C.setCommitmentsArray(comms, commit[i].com, C.int(i))
	//}
	//defer C.freeCommitmentsArray(comms)

	return int(
			C.secp256k1_bulletproof_rangeproof_verify(
				context.ctx,
				scratch.scr,
				generators.gens,
				cBuf(proof),
				C.size_t(len(proof)),
				u64Arr(minvalue),
				commit.com,
				C.size_t(1),
				C.size_t(nbits),
				valuegen.gen,
				cBuf(extracommit),
				C.size_t(len(extracommit)))),
		nil
}

/** Batch-verifies multiple bulletproof (aggregate) rangeproofs of the same size using same generator
 *  Returns: 1: all rangeproofs were valid
 *           0: some rangeproof was invalid, or out of memory
 *  Args:       ctx: pointer to a context object initialized for verification (cannot be NULL)
 *          scratch: scratch space with enough memory for verification (cannot be NULL)
 *             gens: generator set with at least 2*nbits*n_commits many generators (cannot be NULL)
 *  In:       proof: array of byte-serialized rangeproofs (cannot be NULL)
 *         n_proofs: number of proofs in the above array, and number of arrays in the `commit` array
 *             plen: length of every individual proof
 *        min_value: array of arrays of minimum values to prove ranges above, or NULL for all-zeroes
 *           commit: array of arrays of pedersen commitment that the rangeproofs is over (cannot be NULL)
 *        n_commits: number of commitments in each element of the above array (cannot be 0)
 *            nbits: number of bits in each proof
 *        value_gen: generator multiplied by value in pedersen commitments (cannot be NULL)
 *     extra_commit: additonal data committed to by the rangeproof (may be NULL if `extra_commit_len` is 0)
 *     extra_commit_len: array of lengths of additional data
 */
func BulletproofRangeproofVerifyMulti(
	context *Context,
	scratch *ScratchSpace,
	generators *BulletproofGenerators,
	proof [][]byte,
	minvalue []uint64,
	commit []*Commitment,
	nbits int,
	valuegen *Generator,
	extracommit [][]byte,
) (
	int, error,
) {
	var prfmax int
	prfcnt := len(proof)
	proofs := C.makeByteArray(C.int(prfcnt))
	for i := 0; i < prfcnt; i++ {
		prflen := len(proof[i])
		if prflen > prfmax {
			prfmax = prflen
		}
		C.setByteArray(proofs, cBuf(proof[i]), C.int(i))
	}
	defer C.freeByteArray(proofs)

	comcnt := len(commit)
	valcnt := len(minvalue)
	if comcnt != valcnt {
		return 0, errors.New(ErrorBulletproofCount)
	}
	comms := C.makeCommitmentsArray(C.int(comcnt))
	for i := 0; i < comcnt; i++ {
		C.setCommitmentsArray(comms, commit[i].com, C.int(i))
	}
	defer C.freeCommitmentsArray(comms)

	extcnt := len(extracommit)
	extras := C.makeByteArray(C.int(extcnt))
	extlen := make([]C.size_t, extcnt)
	for i := 0; i < extcnt; i++ {
		extlen[i] = C.size_t(len(extracommit[i]))
		C.setByteArray(extras, cBuf(extracommit[i]), C.int(i))
	}
	defer C.freeByteArray(extras)
	/*	// TODO
		return int(
			C.secp256k1_bulletproof_rangeproof_verify_multi(
				context.ctx,
				scratch.scr,
				generators.gens,
				proofs,
				C.size_t(prfcnt),
				C.size_t(prfmax),
				u64Arr(minvalue),
				comms,
				C.size_t(comcnt),
				C.size_t(nbits),
				valuegen.gen,
				extras,
				(*C.ulong)(unsafe.Pointer(&extlen[0])))), nil
	*/
	return 1, nil
}

func sizetArr(goSlice []C.size_t) *C.size_t {
	return (*C.size_t)(unsafe.Pointer(&goSlice[0]))
}

/** Extracts the value and blinding factor from a single-commit rangeproof given a secret nonce
 *  Returns: 1: value and blinding factor were extracted and matched the input commit
 *           0: one of the above was not true, extraction failed
 *  Args:       ctx: pointer to a context object (cannot be NULL)
 *  Out:      value: pointer to value that will be extracted
 *            blind: pointer to 32-byte array for blinding factor to be extracted
 *  In:       proof: byte-serialized rangeproof (cannot be NULL)
 *             plen: length of every individual proof
 *        min_value: minimum value that the proof ranges over
 *           commit: pedersen commitment that the rangeproof is over (cannot be NULL)
 *        value_gen: generator multiplied by value in pedersen commitments (cannot be NULL)
 *            nonce: random 32-byte seed used to derive blinding factors (cannot be NULL)
 *     extra_commit: additional data committed to by the rangeproof
 * extra_commit_len: length of additional data
 *          message: optional 20 bytes of message to recover
 */
func BulletproofRangeproofRewind(
	context *Context,
	proof []byte,
	minvalue uint64,
	commit *Commitment,
	valuegen *Generator,
	nonce [32]byte,
	extracommit []byte,
	message [20]byte,
) (
	status int,
	value uint64,
	blind [32]byte,
	err error,
) {
	var val, minval [2]C.ulong
	minval[0] = C.ulong(minvalue >> 32)
	minval[1] = C.ulong(minvalue & 0xffffffff)
	status = int(
		C.secp256k1_bulletproof_rangeproof_rewind(
			context.ctx,
			&val[0],
			cBuf(blind[:]),
			cBuf(proof),
			C.size_t(len(proof)),
			minval[0],
			commit.com,
			valuegen.gen,
			cBuf(nonce[:]),
			cBuf(extracommit),
			C.size_t(len(extracommit)),
			cBuf(message[:])))
	value = uint64(val[0]<<32 | val[1])
	return
}

/** Produces an aggregate Bulletproof rangeproof for a set of Pedersen commitments
 *
 *  Args:
 *      ctx               pointer to a context object initialized for signing and verification (cannot be NULL)
 *      scratch           scratch space with enough memory for verification (cannot be NULL)
 *      gens              generator set with at least 2*nbits*n_commits many generators (cannot be NULL)
 *  Out:
 *      proof             byte-serialized rangeproof (cannot be NULL)
 *  In/out:
 *      plen              pointer to size of `proof`, to be replaced with actual length of proof (cannot be NULL)
 *      tau_x             only for multi-party; 32-byte, output in second step or input in final step
 *      t_one             only for multi-party; public key, output in first step or input for the others
 *      t_two             only for multi-party; public key, output in first step or input for the others
 *  In:
 *      value             array of values committed by the Pedersen commitments (cannot be NULL)
 *      min_value         array of minimum values to prove ranges above, or NULL for all-zeroes
 *      blind             array of blinding factors of the Pedersen commitments (cannot be NULL)
 *      commits           only for multi-party; array of pointers to commitments
 *      n_commits         number of entries in the `value` and `blind` arrays
 *      value_gen         generator multiplied by value in pedersen commitments (cannot be NULL)
 *      nbits             number of bits proven for each range
 *      nonce             random 32-byte seed used to derive blinding factors (cannot be NULL)
 *      private_nonce     only for multi-party; random 32-byte seed used to derive private blinding factors
 *      extra_commit      additonal data committed to by the rangeproof
 *      extra_commit_len  length of additional data
 *      message           optional 20 bytes of message that can be recovered by rewinding with the correct nonce
 *  Returns:
 *      1                 rangeproof was successfully created
 *      0                 rangeproof could not be created, or out of memory
 */
func BulletproofRangeproofProve(
	context *Context,
	scratch *ScratchSpace,
	generators *BulletproofGenerators,
	taux [32]byte,
	tone *PublicKey,
	ttwo *PublicKey,
	value []uint64,
	minvalue []uint64,
	blind [][32]byte,
	commits []*Commitment,
	valuegen *Generator,
	nbits int,
	nonce [32]byte,
	privatenonce [32]byte,
	extracommit []byte,
	message [20]byte,
) (
	status int,
	proof []byte,
	outaux [32]byte,
	outone *PublicKey,
	outtwo *PublicKey,
	err error,
) {
	output := make([]C.uchar, 2000)
	outputlen := C.size_t(2000)

	n := len(blind)
	if n != len(value) || n != len(minvalue) || n != len(commits) {
		err = errors.New(ErrorBulletproofCount)
		return
	}
	bs := C.makeByteArray(C.int(n))
	cs := C.makeCommitmentsArray(C.int(n))
	for i := 0; i < n; i++ {
		C.setByteArray(bs, cBuf(blind[i][:]), C.int(i))
		C.setCommitmentsArray(cs, commits[i].com, C.int(i))
	}
	defer C.freeByteArray(bs)
	defer C.freeCommitmentsArray(cs)

	status = int(
		C.secp256k1_bulletproof_rangeproof_prove(
			context.ctx,
			scratch.scr,
			generators.gens,
			&output[0],
			&outputlen,
			cBuf(taux[:]),
			tone.pk,
			ttwo.pk,
			u64Arr(value),
			u64Arr(minvalue),
			bs,
			cs,
			C.size_t(n),
			valuegen.gen,
			C.size_t(nbits),
			cBuf(nonce[:]),
			cBuf(privatenonce[:]),
			cBuf(extracommit),
			C.size_t(len(extracommit)),
			cBuf(message[:])))

	proof = goBytes(output, C.int(outputlen))
	outaux = taux
	outone = tone
	outtwo = ttwo

	return
}

/*
    End of Bulletproof section                **
***********************************************/
