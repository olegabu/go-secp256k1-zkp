/* This package implements Zero Knowledge Proof algorithms for Golang
**
** Contains Go bindings for the secp256k1-zkp C-library, which is
** based on the secp256k1 - a highly optimized implementation of the
** 256-bit elliptic curve used in Bitcoin blockchain.
 */
package secp256k1

/*
#include <stddef.h>
#include <stdlib.h>
#include "include/secp256k1_commitment.h"
static const unsigned char** makeBytesArray(int size) { return !size ? NULL : calloc(sizeof(unsigned char*), size); }
static void setBytesArray(unsigned char** a, unsigned char* v, int i) { if (a) a[i] = v; }
static unsigned char* getBytesArray(unsigned char** a, int i) { return !a ? NULL : a[i]; }
static void freeBytesArray(unsigned char** a) { if (a) free(a); }
static secp256k1_pedersen_commitment** makeCommitmentsArray(int size) { return !size ? NULL : calloc(sizeof(secp256k1_pedersen_commitment*), size); }
static void setCommitmentsArray(secp256k1_pedersen_commitment** a, secp256k1_pedersen_commitment* v, int i) { if (a) a[i] = v; }
static secp256k1_pedersen_commitment* getCommitmentsArray(secp256k1_pedersen_commitment** a, int i) { return !a ? NULL : a[i]; }
static void freeCommitmentsArray(secp256k1_pedersen_commitment** a) { if (a) free(a); }
#cgo CFLAGS: -I ${SRCDIR}/secp256k1-zkp -I ${SRCDIR}/secp256k1-zkp/src
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"unsafe"
)

/** Pointer to opaque data structure that stores a base point
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use appropriate serialize and parse functions.
 */
type Commitment struct {
	com *C.secp256k1_pedersen_commitment
}

const (
	ErrorCommitmentParse     string = "unable to parse the data as a commitment"
	ErrorCommitmentSerialize string = "unable to serialize commitment"
	ErrorCommitmentCount     string = "number of elements differ in input arrays"
	// ErrorCommitmentTally     string = "sums of inputs and outputs are not equal"
	ErrorCommitmentCommit string = "failed to create a commitment"
	// ErrorCommitmentBlindSum  string = "failed to calculate sum of blinding factors"
	ErrorCommitmentPubkey string = "failed to create public key from commitment"
)

func makeCommitmentsArray(size int) **C.secp256k1_pedersen_commitment {
	return C.makeCommitmentsArray(C.int(size))
}
func setCommitmentsArray(array **C.secp256k1_pedersen_commitment, value *C.secp256k1_pedersen_commitment, index int) {
	C.setCommitmentsArray(array, value, C.int(index))
}
func getCommitmentsArray(array **C.secp256k1_pedersen_commitment, index int) *C.secp256k1_pedersen_commitment {
	return C.getCommitmentsArray(array, C.int(index))
}
func freeCommitmentsArray(array **C.secp256k1_pedersen_commitment) { C.freeCommitmentsArray(array) }

func newCommitment() *Commitment {
	return &Commitment{
		com: &C.secp256k1_pedersen_commitment{},
	}
}

/** Parse a sequence of bytes as a Pedersen commitment.
 *
 *  Returns: 1 if input contains a valid commitment.
 *  Args: ctx:     a secp256k1 context object.
 *  In:   data:    pointer to a 33-byte serialized data
 *  Out:  nil/Commitment
 */
func CommitmentParse(
	context *Context,
	data33 []byte,
) (
	*Commitment,
	error,
) {
	commit := newCommitment()
	if 1 != C.secp256k1_pedersen_commitment_parse(
		context.ctx,
		commit.com,
		cBuf(data33)) {

		return nil, errors.New(ErrorCommitmentParse + " \"" + hex.EncodeToString(data33) + "\"")
	}

	return commit, nil
}

/** Serialize Commitment into sequence of bytes.
 *
 *  Returns: 1 always.
 *  Args:   ctx:        a secp256k1 context object.
 *  In:     Commitment   a commitment object
 *  Out:    serialized data: 33-byte byte array
 */
func CommitmentSerialize(
	context *Context,
	commit *Commitment,
) (
	data [33]byte,
	err error,
) {
	if 1 != C.secp256k1_pedersen_commitment_serialize(
		context.ctx,
		cBuf(data[:]),
		commit.com) {

		err = errors.New(ErrorCommitmentSerialize)
	}
	return
}

// Convert commitment object to array of bytes
func (commit *Commitment) Bytes() (bytes [33]byte) {
	bytes, _ = CommitmentSerialize(SharedContext(ContextNone), commit)
	return
}

func (commit *Commitment) String() string {
	bytes := commit.Bytes()

	return hex.EncodeToString(bytes[:])
}

func CommitmentFromString(str string) (com *Commitment, err error) {
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return

	}
	com, err = CommitmentParse(SharedContext(ContextNone), bytes)

	return
}

/** Generate a commitment
 *
 *      In:
 *		 ctx:  pointer to a context object (cannot be NULL)
 *             blind:  32-byte blinding factor (cannot be NULL)
 *	       value:  unsigned 64-bit integer value to commit to.
 *    	   value_gen:  value generator 'h'
 *         blind_gen:  blinding factor generator 'g'
 *
 *  	Out:
 *            commit:  pointer to the commitment (cannot be NULL)
 *
 *      Returns:
 *      	   1:  Commitment successfully created.
 *                 0:  Error. The blinding factor is larger than the group order *
 *                     (probability for random 32 byte number < 2^-127) or results in the
 *                     point at infinity. Retry with a different factor.
 *
 *      Blinding factors can be generated and verified in the same way as secp256k1
 *      private keys for ECDSA.
 */
//  SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_pedersen_commit(
// 		const secp256k1_context* ctx,
// 		secp256k1_pedersen_commitment *commit,
// 		const unsigned char *blind,
// 		uint64_t value,
// 		const secp256k1_generator *value_gen,
// 		const secp256k1_generator *blind_gen
//  ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);
func Commit(
	context *Context,
	blind []byte,
	value uint64,
	valuegen *Generator,
	blindgen *Generator,
) (
	commit *Commitment,
	err error,
) {
	commit = newCommitment()
	if 1 != C.secp256k1_pedersen_commit(
		context.ctx,
		commit.com,
		cBuf(blind),
		C.uint64_t(value),
		valuegen.gen,
		blindgen.gen) {

		return nil, errors.New(ErrorCommitmentCommit)
	}
	return
}

/** Generate a commitment from two blinding factors.
 *  Returns 1: Commitment successfully created.
 *          0: Error. The blinding factor is larger than the group order
 *             (probability for random 32 byte number < 2^-127) or results in the
 *             point at infinity. Retry with a different factor.
 *  In:     ctx:        pointer to a context object (cannot be NULL)
 *          blind:      pointer to a 32-byte blinding factor (cannot be NULL)
 *          value:      pointer to a 32-byte blinding factor (cannot be NULL)
 *          value_gen:  value generator 'h'
 *          blind_gen:  blinding factor generator 'g'
 *  Out:    commit:     pointer to the commitment (cannot be NULL)
 *
 *  Blinding factors can be generated and verified in the same way as secp256k1 private keys for ECDSA.
 */
func BlindCommit(
	context *Context,
	blind []byte,
	value []byte,
	valuegen *Generator,
	blindgen *Generator,
) (
	commit *Commitment,
	err error,
) {
	commit = newCommitment()
	if 1 != C.secp256k1_pedersen_blind_commit(
		context.ctx,
		commit.com,
		cBuf(blind),
		cBuf(value),
		valuegen.gen,
		blindgen.gen) {

		return nil, errors.New("error creating commitments from two blinds")
	}
	return commit, nil
}

/** Computes the sum of multiple positive and negative blinding factors.
 *
 *  Returns 1: Sum successfully computed.
 *          0: Error. A blinding factor is larger than the group order
 *             (probability for random 32 byte number < 2^-127). Retry with
 *             different factors.
 *
 *  In:     ctx:        pointer to a context object (cannot be NULL)
 *          blinds:     pointer to pointers to 32-byte character arrays for blinding factors. (cannot be NULL)
 *          n:          number of factors pointed to by blinds.
 *          npositive:  how many of the input factors should be treated with a positive sign.
 *
 *  Out:    blind_out:  pointer to a 32-byte array for the sum (cannot be NULL)
 */
/* SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_pedersen_blind_sum(
//  const secp256k1_context* ctx,
//  unsigned char *blind_out,
//  const unsigned char * const *blinds,
//  size_t n,
//  size_t npositive  */
func BlindSum(
	context *Context,
	posblinds [][]byte,
	negblinds [][]byte,
) (
	sum [32]byte,
	err error,
) {
	npositive := len(posblinds)
	ntotal := npositive + len(negblinds)

	blinds := C.makeBytesArray(C.int(ntotal))
	defer C.freeBytesArray(blinds)

	for pi, pb := range posblinds {
		C.setBytesArray(blinds, cBuf(pb), C.int(pi))
	}

	for ni, nb := range negblinds {
		C.setBytesArray(blinds, cBuf(nb), C.int(npositive+ni))
	}

	if 1 != C.secp256k1_pedersen_blind_sum(
		context.ctx,
		cBuf(sum[:]),
		blinds,
		C.size_t(C.int(ntotal)),
		C.size_t(C.int(npositive))) {

		err = errors.New("error calculating sum of blinds")
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
 */
func CommitSum(
	context *Context,
	poscommits []*Commitment,
	negcommits []*Commitment,
) (
	sum *Commitment,
	err error,
) {
	posarr := makeCommitmentsArray(len(poscommits))
	defer freeCommitmentsArray(posarr)
	for pi, pc := range poscommits {
		setCommitmentsArray(posarr, pc.com, pi)
	}

	negarr := makeCommitmentsArray(len(negcommits))
	defer freeCommitmentsArray(negarr)
	for ni, nc := range negcommits {
		setCommitmentsArray(negarr, nc.com, ni)
	}

	sum = newCommitment()
	if 1 != C.secp256k1_pedersen_commit_sum(
		context.ctx,
		sum.com,
		posarr, C.size_t(len(poscommits)),
		negarr, C.size_t(len(negcommits))) {

		err = errors.New("error calculating sum of commitments")
	}

	return
}

/** Verify a tally of Pedersen commitments
 * Returns 1: commitments successfully sum to zero.
 *         0: Commitments do not sum to zero or other error.
 * In:     ctx:    pointer to a context object (cannot be NULL)
 *         pos:    pointer to array of pointers to the commitments. (cannot be NULL if `n_pos` is non-zero)
 *         n_pos:  number of commitments pointed to by `pos`.
 *         neg:    pointer to array of pointers to the negative commitments. (cannot be NULL if `n_neg` is non-zero)
 *         n_neg:  number of commitments pointed to by `neg`.
 *
 * This computes sum(pos[0..n_pos)) - sum(neg[0..n_neg)) == 0.
 *
 * A Pedersen commitment is xG + vA where G and A are generators for the secp256k1 group and x is a blinding factor,
 * while v is the committed value. For a collection of commitments to sum to zero, for each distinct generator
 * A all blinding factors and all values must sum to zero.
 *
 */
func VerifyTally(
	context *Context,
	poscommits []*Commitment,
	negcommits []*Commitment,
) (
	err error,
) {
	posarr := makeCommitmentsArray(len(poscommits))
	defer freeCommitmentsArray(posarr)
	for pi, pc := range poscommits {
		setCommitmentsArray(posarr, pc.com, pi)
	}

	negarr := makeCommitmentsArray(len(negcommits))
	defer freeCommitmentsArray(negarr)
	for ni, nc := range negcommits {
		setCommitmentsArray(negarr, nc.com, ni)
	}

	if 1 != C.secp256k1_pedersen_verify_tally(
		context.ctx,
		posarr, C.size_t(len(poscommits)),
		negarr, C.size_t(len(negcommits))) {

		err = errors.New("commitments do not sum to zero or other error")
	}

	return
}

/** Sets the final Pedersen blinding factor correctly when the generators themselves
 *  have blinding factors.
 *
 * Consider a generator of the form A' = A + rG, where A is the "real" generator
 * but A' is the generator provided to verifiers. Then a Pedersen commitment
 * P = vA' + r'G really has the form vA + (vr + r')G. To get all these (vr + r')
 * to sum to zero for multiple commitments, we take three arrays consisting of
 * the `v`s, `r`s, and `r'`s, respectively called `value`s, `generator_blind`s
 * and `blinding_factor`s, and sum them.
 *
 * The function then subtracts the sum of all (vr + r') from the last element
 * of the `blinding_factor` array, setting the total sum to zero.
 *
 * Returns 1: Blinding factor successfully computed.
 *         0: Error. A blinding_factor or generator_blind are larger than the group
 *            order (probability for random 32 byte number < 2^-127). Retry with
 *            different values.
 *
 * In:                 ctx: pointer to a context object
 *                   value: array of asset values, `v` in the above paragraph.
 *                          May not be NULL unless `n_total` is 0.
 *         generator_blind: array of asset blinding factors, `r` in the above paragraph
 *                          May not be NULL unless `n_total` is 0.
 *                 n_total: Total size of the above arrays
 *                n_inputs: How many of the initial array elements represent commitments that
 *                          will be negated in the final sum
 * In/Out: blinding_factor: array of commitment blinding factors, `r'` in the above paragraph
 *                          May not be NULL unless `n_total` is 0.
 *                          the last value will be modified to get the total sum to zero.
 */
func BlindGeneratorBlindSum(
	context *Context,
	value []uint64,
	generatorblind [][]byte,
	blindingfactor [][]byte,
	ninputs int,
) (
	results [][32]byte,
	err error,
) {
	vbl := len(value)
	gbl := len(generatorblind)
	fbl := len(blindingfactor)
	if vbl != gbl || gbl != fbl {
		return nil, errors.New(ErrorCommitmentCount)
	}
	gbls := C.makeBytesArray(C.int(vbl))
	fbls := C.makeBytesArray(C.int(vbl))
	for i := 0; i < vbl; i++ {
		C.setBytesArray(gbls, cBuf(generatorblind[i]), C.int(i))
		C.setBytesArray(fbls, cBuf(blindingfactor[i]), C.int(i))
	}
	defer C.freeBytesArray(gbls)
	defer C.freeBytesArray(fbls)

	if 1 != C.secp256k1_pedersen_blind_generator_blind_sum(
		context.ctx,
		u64Arr(value),
		gbls,
		fbls,
		C.size_t(vbl),
		C.size_t(ninputs)) {

		return nil, errors.New(ErrorCommitmentCommit)
	}

	// Copy output from fbls
	results = make([][32]byte, vbl)
	for i := 0; i < vbl; i++ {
		b := C.getBytesArray(fbls, C.int(i))
		copy(results[i][:], C.GoBytes(unsafe.Pointer(b), 32))
	}

	return results, nil
}

/** Calculates the blinding factor x' = x + SHA256(xG+vH | xJ), used in the switch commitment x'G+vH
 *
 * Returns 1: Blinding factor successfully computed.
 *         0: Error. Retry with different values.
 *
 * Args:           ctx: pointer to a context object
 * Out:   blind_switch: blinding factor for the switch commitment
 * In:           blind: pointer to a 32-byte blinding factor
 *               value: unsigned 64-bit integer value to commit to
 *           value_gen: value generator 'h'
 *           blind_gen: blinding factor generator 'g'
 *       switch_pubkey: pointer to public key 'j'
 */
func BlindSwitch(
	context *Context,
	blind []byte,
	value uint64,
	valuegen *Generator,
	blindgen *Generator,
	switchpubkey *PublicKey,
) (
	result [32]byte,
	err error,
) {
	if 1 != C.secp256k1_blind_switch(
		context.ctx,
		cBuf(result[:]),
		cBuf(blind),
		C.uint64_t(value),
		valuegen.gen,
		blindgen.gen,
		switchpubkey.pk) {

		err = errors.New(ErrorCommitmentCommit)
	}
	return
}

/** Converts a pedersent commit to a pubkey
 *
 * Returns 1: Public key succesfully computed.
 *         0: Error.
*
 * In:                 ctx: pointer to a context object
 *                   commit: pointer to a single commit
 * Out:              pubkey: resulting pubkey
 *
*/
func CommitmentToPublicKey(
	context *Context,
	commit *Commitment,
) (
	pubkey *PublicKey,
	err error,
) {
	pubkey = newPublicKey()
	if 1 != C.secp256k1_pedersen_commitment_to_pubkey(
		context.ctx,
		pubkey.pk,
		commit.com) {

		return nil, errors.New(ErrorCommitmentPubkey)
	}
	return pubkey, nil
}
