package secp256k1

/*
#cgo CFLAGS: -I ${SRCDIR}/secp256k1-zkp -I ${SRCDIR}/secp256k1-zkp/src
#include <stdlib.h>
#define USE_BASIC_CONFIG 1
#define ECMULT_GEN_PREC_BITS 4
#include "basic-config.h"
#include "include/secp256k1.h"
#include "group.h"
#include "util.h"
#include "include/secp256k1_generator.h"
#include "include/secp256k1_rangeproof.h"
//#include "modules/rangeproof/main_impl.h"
static const unsigned char** makeBytesArray(int size) { return !size ? NULL : calloc(sizeof(unsigned char*), size); }
static void setBytesArray(unsigned char** a, unsigned char* v, int i) { if (a) a[i] = v; }
static unsigned char* getBytesArray(unsigned char** a, int i) { return !a ? NULL : a[i]; }
static void freeBytesArray(unsigned char** a) { if (a) free(a); }
static secp256k1_pedersen_commitment** makeCommitmentsArray(int size) { return !size ? NULL : calloc(sizeof(secp256k1_pedersen_commitment*), size); }
static void setCommitmentsArray(secp256k1_pedersen_commitment** a, secp256k1_pedersen_commitment* v, int i) { if (a) a[i] = v; }
static secp256k1_pedersen_commitment* getCommitmentsArray(secp256k1_pedersen_commitment** a, int i) { return !a ? NULL : a[i]; }
static void freeCommitmentsArray(secp256k1_pedersen_commitment** a) { if (a) free(a); }
// Takes two lists of 33-byte commitments and sums the first set, subtracts the second and returns the resulting commitment.
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"unsafe"
)

const (
	// MaxRangeproofSize is the max size in bytes of a range proof
	MaxRangeproofSize = 5134

	ErrorRangeproof       string = "failed to create a range proof"
	ErrorRangeproofInfo   string = "failed to retrieve info for range proof"
	ErrorRangeproofRewind string = "failed to recover information about author of range proof"
)

const (
	ErrorCommitmentParse     string = "unable to parse the data as a commitment"
	ErrorCommitmentSerialize string = "unable to serialize commitment"
	ErrorCommitmentCount     string = "number of elements differ in input arrays"
	ErrorCommitmentTally     string = "sums of inputs and outputs are not equal"
	ErrorCommitmentCommit    string = "failed to create a commitment"
	ErrorCommitmentSwitch    string = "failed to calcultate switch commitment"
	ErrorCommitmentBlindSum  string = "failed to calcluate sum of blinding factors"
	ErrorCommitmentPubkey    string = "failed to create public key from commitment"
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

/** Pointer to opaque data structure that stores a base point
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use appropriate serialize and parse functions.
 */
type Commitment = C.secp256k1_pedersen_commitment

/** Parse a sequence of bytes as a Pedersen commitment.
 *
 *  Returns: 1 if input contains a valid commitment.
 *  Args: ctx:     a secp256k1 context object.
 *  In:   data:    pointer to a 33-byte serialized data
 *  Out:  nil/Commitment
 */
func CommitmentParse(context *Context, bytes33 []byte) (*Commitment, error) {
	var commit Commitment
	if 1 != C.secp256k1_pedersen_commitment_parse(context.ctx, &commit, cBuf(bytes33)) {
		return nil, errors.New(ErrorCommitmentParse)
	}
	return &commit, nil
}

/** Serialize Commitment into sequence of bytes.
 *
 *  Returns: 1 always.
 *  Args:   ctx:        a secp256k1 context object.
 *  In:     Commitment   a commitment object
 *  Out:    serialized data: 33-byte byte array
 */
func CommitmentSerialize(context *Context, commit *Commitment) (bytes [33]byte, err error) {
	if 1 != C.secp256k1_pedersen_commitment_serialize(context.ctx, cBuf(bytes[:]), commit) {
		err = errors.New(ErrorCommitmentSerialize)
	}
	return
}

// Convert commitment object to array of bytes
func (commit *Commitment) Bytes() (bytes [33]byte) {
	bytes, _ = CommitmentSerialize(SharedContext(ContextNone), commit)
	return
}

// Convert commitment object to a hex string
func (commit *Commitment) String() string {
	bytes, _ := CommitmentSerialize(SharedContext(ContextNone), commit)
	return hex.EncodeToString(bytes[:])
}

// Try to convert a hex string into an Commitment object
func CommitmentFromString(str string) (*Commitment, error) {
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return CommitmentParse(SharedContext(ContextNone), bytes)
}

/** Generate a pedersen commitment.
 *  Returns 1: Commitment successfully created.
 *          0: Error. The blinding factor is larger than the group order
 *             (probability for random 32 byte number < 2^-127) or results in the
 *             point at infinity. Retry with a different factor.
 *  In:     ctx:        pointer to a context object, initialized for signing and Pedersen commitment (cannot be NULL)
 *          blind:      pointer to a 32-byte blinding factor (cannot be NULL)
 *          value:      unsigned 64-bit integer value to commit to.
 *          gen:        additional generator 'h'
 *  Out:    commit:     pointer to the commitment (cannot be NULL)
 *
 *  Blinding factors can be generated and verified in the same way as secp256k1 private keys for ECDSA.
 */
func Commit(
	context *Context,
	blind []byte,
	value uint64,
	valuegen *Generator,
) (
	*Commitment,
	error,
) {
	var commit Commitment
	if 1 != C.secp256k1_pedersen_commit(
		context.ctx,
		&commit,
		cBuf(blind),
		C.uint64_t(value),
		valuegen.gen,
	) {
		return nil, errors.New(ErrorCommitmentCommit)
	}
	/*SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_pedersen_commit(
	   	const secp256k1_context* ctx,
	   	secp256k1_pedersen_commitment *commit,
	   	const unsigned char *blind,
	   	uint64_t value,
	   	const secp256k1_generator *gen
	) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5);*/
	return &commit, nil
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

		err = errors.New(ErrorCommitmentBlindSum)
	}
	/*SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_pedersen_blind_sum(
	const secp256k1_context* ctx,
	unsigned char *blind_out,
	const unsigned char * const *blinds,
	size_t n,
	size_t npositive)*/
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
		b := getBytesArray(fbls, i)
		copy(results[i][:], C.GoBytes(unsafe.Pointer(b), 32))
	}

	return results, nil
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
	/*posarr := makeCommitmentsArray(len(poscommits))
	defer freeCommitmentsArray(posarr)
	for pi, pc := range poscommits {
		setCommitmentsArray(posarr, pc.com, pi)
	}

	negarr := makeCommitmentsArray(len(negcommits))
	defer freeCommitmentsArray(negarr)
	for ni, nc := range negcommits {
		setCommitmentsArray(negarr, nc.com, ni)
	}*/

	if 1 != C.secp256k1_pedersen_verify_tally(
		context.ctx,
		&poscommits[0], C.size_t(len(poscommits)),
		&negcommits[0], C.size_t(len(negcommits))) {

		err = errors.New(ErrorCommitmentTally)
	}

	return
}

/* RangeproofSign authors a proof that a committed value is within a range.
 *
 * 	 Returns 1: Proof successfully created.
 *           0: Error
 * 	 In:     ctx:    pointer to a context object, initialized for range-proof, signing, and Pedersen commitment (cannot be NULL)
 *           proof:  pointer to array to receive the proof, can be up to 5134 bytes. (cannot be NULL)
 *           min_value: constructs a proof where the verifer can tell the minimum value is at least the specified amount.
 *           commit: the commitment being proved.
 *           blind:  32-byte blinding factor used by commit.
 *           nonce:  32-byte secret nonce used to initialize the proof (value can be reverse-engineered out of the proof if this secret is known.)
 *           exp:    Base-10 exponent. Digits below above will be made public, but the proof will be made smaller. Allowed range is -1 to 18.
 *                   (-1 is a special case that makes the value public. 0 is the most private.)
 *           min_bits: Number of bits of the value to keep private. (0 = auto/minimal, - 64).
 *           value:  Actual value of the commitment.
 *           message: pointer to a byte array of data to be embedded in the rangeproof that can be recovered by rewinding the proof
 *           extra_commit: additional data to be covered in rangeproof signature
 *           gen: additional generator 'h'
 *
 * If min_value or exp is non-zero then the value must be on the range [0, 2^63) to prevent the proof range from spanning past 2^64.
 *
 * If exp is -1 the value is revealed by the proof (e.g. it proves that the proof is a blinding of a specific value, without revealing the blinding key.)
 *
 * This can randomly fail with probability around one in 2^100. If this happens, buy a lottery ticket and retry with a different nonce or blinding.
 *
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_rangeproof_sign(
  const secp256k1_context* ctx,
  unsigned char *proof,
  size_t *plen,
  uint64_t min_value,
  const secp256k1_pedersen_commitment *commit,
  const unsigned char *blind,
  const unsigned char *nonce,
  int exp,
  int min_bits,
  uint64_t value,
  const unsigned char *message,
  size_t msg_len,
  const unsigned char *extra_commit,
  size_t extra_commit_len,
  const secp256k1_generator *gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(15);
*/
func RangeproofSign(
	context *Context,
	minValue uint64,
	commit *Commitment,
	blindingFactor []byte,
	nonce []byte,
	exp, minBits int,
	value uint64,
	message []byte,
	extracommit []byte,
	generator *Generator,
) (
	proof []byte,
	err error,
) {
	var cproof [MaxRangeproofSize]byte
	var cprooflen C.size_t = MaxRangeproofSize

	if 1 != C.secp256k1_rangeproof_sign(
		context.ctx,
		cBuf(cproof[:]),
		&cprooflen,
		C.uint64_t(minValue),
		commit,
		cBuf(blindingFactor),
		cBuf(nonce),
		C.int(exp),
		C.int(minBits),
		C.uint64_t(value),
		cBuf(message),
		C.size_t(len(message)),
		cBuf(extracommit),
		C.size_t(len(extracommit)),
		generator.gen,
	) {
		err = errors.New(ErrorRangeproof)
	} else {
		proof = cproof[:int(cprooflen)]
	}

	return
}

/* RangeproofInfo extracts some basic information from a range-proof.
 *
 * 	 Returns 1: Information successfully extracted.
 *         	 0: Decode failed.
 * 	 In:   	 ctx: pointer to a context object
 *       	 	 proof: pointer to character array with the proof.
 * 	 Out:  	 exp: Exponent used in the proof (-1 means the value isn't private).
 *       	 	 mantissa: Number of bits covered by the proof.
 *       	 	 min_value: pointer to an unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
 */
func RangeproofInfo(
	context *Context,
	proof []byte,
) (
	exp int,
	mantissa int,
	minValue uint64,
	maxValue uint64,
	err error,
) {
	if 1 != C.secp256k1_rangeproof_info(
		context.ctx,
		(*C.int)(unsafe.Pointer(&exp)),
		(*C.int)(unsafe.Pointer(&mantissa)),
		(*C.uint64_t)(unsafe.Pointer(&minValue)),
		(*C.uint64_t)(unsafe.Pointer(&maxValue)),
		cBuf(proof),
		C.size_t(len(proof)),
	) {
		err = errors.New(ErrorRangeproofInfo)
		return
	}

	return
}

/* RangeproofVerify verifies a proof that a committed value is within a range.
 * 	 Returns 1: Value is within the range [0..2^64), the specifically proven range is in the min/max value outputs.
 *         	 0: Proof failed or other error.
 * 	 In:   	 ctx: pointer to a context object, initialized for range-proof and commitment (cannot be NULL)
 *       	 	 commit: the commitment being proved. (cannot be NULL)
 *       	 	 proof: pointer to character array with the proof. (cannot be NULL)
 *      	 	 extra_commit: additional data covered in rangeproof signature
 *       	 	 gen: additional generator 'h'
 * 	 Out:  	 min_value: pointer to a unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
 *       	 	 max_value: pointer to a unsigned int64 which will be updated with the maximum value that commit could have. (cannot be NULL)
 *
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_rangeproof_verify(
  const secp256k1_context* ctx,
  uint64_t *min_value,
  uint64_t *max_value,
  const secp256k1_pedersen_commitment *commit,
  const unsigned char *proof,
  size_t plen,
  const unsigned char *extra_commit,
  size_t extra_commit_len,
  const secp256k1_generator* gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(9);
*/
func RangeproofVerify(
	context *Context,
	proof []byte,
	commit *Commitment,
	extraCommit []byte,
	generator *Generator,
) bool {
	var cExtraCmt *C.uchar
	cExtraCmtLen := 0

	if extraCommit != nil && len(extraCommit) > 0 {
		cExtraCmt = cBuf(extraCommit)
		cExtraCmtLen = len(extraCommit)
	}

	minValue := 0
	maxValue := 0

	if 1 != C.secp256k1_rangeproof_verify(
		context.ctx,
		(*C.uint64_t)(unsafe.Pointer(&minValue)),
		(*C.uint64_t)(unsafe.Pointer(&maxValue)),
		commit,
		cBuf(proof),
		C.size_t(len(proof)),
		cExtraCmt,
		C.size_t(cExtraCmtLen),
		generator.gen,
	) {
		return false
	}

	return true
}

/* RangeproofRewind verifies a range proof and rewind the proof to recover information sent by its author.
 *	 Returns 1: Value is within the range [0..2^64), the specifically proven range is in the min/max value outputs, and the value and blinding were recovered.
 *           0: Proof failed, rewind failed, or other error.
 *	 In:   	 ctx: pointer to a context object, initialized for range-proof and Pedersen commitment (cannot be NULL)
 *        	 commit: the commitment being proved. (cannot be NULL)
 *        	 proof: pointer to character array with the proof. (cannot be NULL)
 *        	 nonce: 32-byte secret nonce used by the prover (cannot be NULL)
 *        	 extra_commit: additional data covered in rangeproof signature
 *        	 gen: additional generator 'h'
 * 	 In/Out: blind_out: storage for the 32-byte blinding factor used for the commitment
 *        	 value_out: pointer to an unsigned int64 which has the exact value of the commitment.
 *        	 message_out: pointer to a 4096 byte character array to receive message data from the proof author.
 *        	 outlen:  length of message data written to message_out.
 *        	 min_value: pointer to an unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
 *        	 max_value: pointer to an unsigned int64 which will be updated with the maximum value that commit could have. (cannot be NULL)
 *
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_rangeproof_rewind(
  const secp256k1_context* ctx,
  unsigned char *blind_out,
  uint64_t *value_out,
  unsigned char *message_out,
  size_t *outlen,
  const unsigned char *nonce,
  uint64_t *min_value,
  uint64_t *max_value,
  const secp256k1_pedersen_commitment *commit,
  const unsigned char *proof,
  size_t plen,
  const unsigned char *extra_commit,
  size_t extra_commit_len,
  const secp256k1_generator *gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8) SECP256K1_ARG_NONNULL(9) SECP256K1_ARG_NONNULL(10) SECP256K1_ARG_NONNULL(14);
*/
func RangeproofRewind(
	context *Context,
	commit *Commitment,
	proof []byte,
	nonce [32]byte,
	extraCommit []byte,
	gen *Generator,
) (
	blindingFactor [32]byte,
	value, minValue, maxValue uint64,
	message []byte,
	err error,
) {
	var cExtraCmt *C.uchar
	cExtraCmtLen := 0
	if extraCommit != nil && len(extraCommit) > 0 {
		cExtraCmt = cBuf(extraCommit)
		cExtraCmtLen = len(extraCommit)
	}

	var msg [4096]byte
	msgLen := uint64(64)

	if 1 != C.secp256k1_rangeproof_rewind(
		context.ctx,
		cBuf(blindingFactor[:]),
		(*C.uint64_t)(unsafe.Pointer(&value)),
		cBuf(msg[:]),
		(*C.size_t)(unsafe.Pointer(&msgLen)),
		cBuf(nonce[:]),
		(*C.uint64_t)(unsafe.Pointer(&minValue)),
		(*C.uint64_t)(unsafe.Pointer(&maxValue)),
		commit,
		cBuf(proof),
		(C.size_t)(len(proof)),
		cExtraCmt,
		C.size_t(cExtraCmtLen),
		gen.gen,
	) {
		err = errors.New(ErrorRangeproofRewind)
		return
	}
	message = make([]byte, msgLen)
	copy(message, msg[:msgLen])

	return
}
