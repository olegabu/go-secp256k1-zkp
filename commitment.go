/* This package implements Zero Knowledge Proof algorithms for Golang
**
** Contains Go bindings for the secp256k1-zkp C-library, which is
** based on the secp256k1 - a highly optimized implementation of the
** 256-bit elliptic curve used in Bitcoin blockchain.
 */
package secp256k1

/*
#include <stdlib.h>
#include "include/secp256k1_commitment.h"
static unsigned char** makeBytesArray(int size) { return !size ? NULL : calloc(sizeof(unsigned char*), size); }
static void setBytesArray(unsigned char** a, unsigned char* v, int i) { if (a) a[i] = v; }
static unsigned char* getBytesArray(unsigned char** a, int i) { return !a ? NULL : a[i]; }
static void freeBytesArray(unsigned char** a) { if (a) free(a); }
static secp256k1_pedersen_commitment** makeCommitmentsArray(int size) { return !size ? NULL : calloc(sizeof(secp256k1_pedersen_commitment*), size); }
static void setCommitmentsArray(secp256k1_pedersen_commitment** a, secp256k1_pedersen_commitment* v, int i) { if (a) a[i] = v; }
static void freeCommitmentsArray(secp256k1_pedersen_commitment** a) { if (a) free(a); }
*/
//#cgo CFLAGS: -I ${SRCDIR}/secp256k1-zkp -I ${SRCDIR}/secp256k1-zkp/src
import "C"
import (
	"encoding/hex"
	"errors"
	"unsafe"
)

type BlindingFactor [32]byte

/** Pointer to opaque data structure that stores a base point
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use appropriate serialize and parse functions.
 */
type Commitment struct {
	context *Context
	com     *C.secp256k1_pedersen_commitment
}

const (
	ErrorCommitmentSize  string = "Commitment data expected length is 33 bytes"
	ErrorCommitmentParse string = "Unable to parse the data as a commitment"
	ErrorCommitmentCount string = "Number of elements differ in input arrays"
)

func newCommitment(ctx *Context) *Commitment {
	return &Commitment{
		context: ctx,
		com:     &C.secp256k1_pedersen_commitment{},
	}
}

/** Parse a sequence of bytes as a Pedersen commitment.
 *
 *  Returns: 1 if input contains a valid commitment.
 *  Args: ctx:     a secp256k1 context object.
 *  In:   data:    pointer to a 33-byte serialized data
 *  Out:  status, Commitment, error
 */
func CommitmentParse(
	context *Context,
	data []byte,
) (
	success bool,
	commitment *Commitment,
	failure error,
) {
	l := len(data)
	if l != LenCompressed {
		return false, nil, errors.New(ErrorCommitmentSize)
	}
	commitment = newCommitment(context)
	success = 1 == int(
		C.secp256k1_pedersen_commitment_parse(
			context.ctx,
			commitment.com,
			cBuf(data)))
	return
}

/** Serialize Commitment into sequence of bytes.
 *
 *  Returns: 1 always.
 *  Args:   ctx:        a secp256k1 context object.
 *  In:     Commitment   a commitment object
 *  Out:    status, data, error:     a pointer to a 33-byte byte array
 */
func CommitmentSerialize(
	context *Context,
	commitment *Commitment,
) (
	success bool,
	data [33]byte,
	failure error,
) {
	success = 1 == int(
		C.secp256k1_pedersen_commitment_serialize(
			context.ctx,
			cBuf(data[:]),
			commitment.com))
	return
}

func (commitment *Commitment) Bytes() (bytes []byte) {
	_, bb, _ := CommitmentSerialize(commitment.context, commitment)
	return bb[:]
}

/*func (commitment *Commitment) Parse(bytes [33]byte) error {
	success, com, err := CommitmentParse(commitment.context, commitment)
	if error != nil {
		return err
	}
	if !success {
		return error.New("Parsing error")
	}
	commitment.com = com.com
	return nil
}*/

func (commitment *Commitment) Hex() (str string) {
	return hex.EncodeToString(commitment.Bytes())
}

/*func (commitment *Commitment) HexParse(str string) error {
	commbytes, err := hex.DecodeString(str)
	if err != nil {
		return err
	}
	return commitment.Parse(commbytes)
}*/

///** Initialize context for usage with Pedersen commitments.
// *
// *   In:
// * 	     context:  context object to be iniitialized
// */
//func ContextInitialize(context *Context) {
//	C.secp256k1_pedersen_context_initialize(context.ctx)
//}

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
func Commit(
	context *Context,
	blind [32]byte,
	value uint64,
	valuegen *Generator,
	blindgen *Generator,
) (
	bool,
	*Commitment,
	error,
) {
	commit := newCommitment(context)
	status := int(
		C.secp256k1_pedersen_commit(
			context.ctx,
			commit.com,
			cBuf(blind[:]),
			C.uint64_t(value),
			valuegen.gen,
			blindgen.gen))

	return status == 1, commit, nil
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
	blind [32]byte,
	value [32]byte,
	valuegen *Generator,
	blindgen *Generator,
) (
	bool,
	*Commitment,
	error,
) {
	commit := newCommitment(context)
	status := int(
		C.secp256k1_pedersen_blind_commit(
			context.ctx,
			commit.com,
			cBuf(blind[:]),
			cBuf(value[:]),
			valuegen.gen,
			blindgen.gen))

	return status == 1, commit, nil
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
func BlindSum(
	context *Context,
	blinds [][32]byte,
	npositive int,
) (
	success bool,
	blindout [32]byte,
	failure error,
) {
	bl := len(blinds)
	bs := C.makeBytesArray(C.int(bl))
	for i := 0; i < bl; i++ {
		C.setBytesArray(bs, cBuf(blinds[i][:]), C.int(i))
	}
	defer C.freeBytesArray(bs)

	success = 1 == int(
		C.secp256k1_pedersen_blind_sum(
			context.ctx,
			cBuf(blindout[:]),
			bs,
			C.size_t(bl),
			C.size_t(npositive)))

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
	bool, *Commitment, error,
) {
	poscnt := len(poscommits)
	posarr := C.makeCommitmentsArray(C.int(poscnt))
	for i := 0; i < poscnt; i++ {
		C.setCommitmentsArray(posarr, poscommits[i].com, C.int(i))
	}
	defer C.freeCommitmentsArray(posarr)

	negcnt := len(negcommits)
	negarr := C.makeCommitmentsArray(C.int(negcnt))
	for i := 0; i < negcnt; i++ {
		C.setCommitmentsArray(negarr, negcommits[i].com, C.int(i))
	}
	defer C.freeCommitmentsArray(negarr)

	commit := newCommitment(context)
	status := int(
		C.secp256k1_pedersen_commit_sum(
			context.ctx,
			commit.com,
			posarr, C.size_t(poscnt),
			negarr, C.size_t(negcnt)))

	return status == 1, commit, nil
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
	success bool,
	failure error,
) {
	poscnt := len(poscommits)
	posarr := C.makeCommitmentsArray(C.int(poscnt))
	for i := 0; i < poscnt; i++ {
		C.setCommitmentsArray(
			posarr,
			poscommits[i].com,
			C.int(i))
	}
	defer C.freeCommitmentsArray(posarr)

	negcnt := len(negcommits)
	negarr := C.makeCommitmentsArray(C.int(negcnt))
	for i := 0; i < negcnt; i++ {
		C.setCommitmentsArray(
			negarr,
			negcommits[i].com,
			C.int(i))
	}
	defer C.freeCommitmentsArray(negarr)

	success = 1 == int(
		C.secp256k1_pedersen_verify_tally(
			context.ctx,
			posarr,
			C.size_t(poscnt),
			negarr,
			C.size_t(negcnt)))
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
	generatorblind [][32]byte,
	blindingfactor [][32]byte,
	ninputs int,
) (
	success bool,
	blindings [][32]byte,
	failure error,
) {
	vbl := len(value)
	gbl := len(generatorblind)
	fbl := len(blindingfactor)
	if vbl != gbl || gbl != fbl {
		return false, nil, errors.New(ErrorCommitmentCount)
	}
	gbls := C.makeBytesArray(C.int(vbl))
	fbls := C.makeBytesArray(C.int(vbl))
	for i := 0; i < vbl; i++ {
		C.setBytesArray(gbls, cBuf(generatorblind[i][:]), C.int(i))
		C.setBytesArray(fbls, cBuf(blindingfactor[i][:]), C.int(i))
	}
	defer C.freeBytesArray(gbls)
	defer C.freeBytesArray(fbls)

	success = 1 == int(
		C.secp256k1_pedersen_blind_generator_blind_sum(
			context.ctx,
			u64Arr(value),
			gbls,
			fbls,
			C.size_t(vbl),
			C.size_t(ninputs)))

	// Copy output from fbls
	blindings = make([][32]byte, vbl)
	for i := 0; i < vbl; i++ {
		b := C.getBytesArray(fbls, C.int(i))
		copy(blindings[i][:], C.GoBytes(unsafe.Pointer(b), 32))
	}

	return
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
	blind [32]byte,
	value uint64,
	valuegen *Generator,
	blindgen *Generator,
	switchpubkey *PublicKey,
) (
	success bool,
	blindswitch [32]byte,
	failure error,
) {
	success = 1 == int(
		C.secp256k1_blind_switch(
			context.ctx,
			cBuf(blindswitch[:]),
			cBuf(blind[:]),
			C.uint64_t(value),
			valuegen.gen,
			blindgen.gen,
			switchpubkey.pk))
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
	success bool,
	pubkey *PublicKey,
	failure error,
) {
	pubkey = newPublicKey()
	success = 1 == int(
		C.secp256k1_pedersen_commitment_to_pubkey(
			context.ctx,
			pubkey.pk,
			commit.com))
	return
}
