package secp256k1

/*
   #include "include/secp256k1_generator.h"
   #include "include/secp256k1_rangeproof.h"
   #cgo CFLAGS: -I${SRCDIR}/secp256k1-zkp -I${SRCDIR}/secp256k1-zkp/src
*/
import "C"
import (
	"errors"
	"unsafe"
)

const (
	// MaxRangeProofSize is the max size in bytes of a range proof
	MaxRangeProofSize = 5134

	ErrRangeProof       string = "failed to create a range proof"
	ErrRangeProofInfo   string = "failed to retrieve info for range proof"
	ErrRangeProofRewind string = "failed to recover information about author of range proof"
)

// RangeProofSign authors a proof that a committed value is within a range.
//
// 	 Returns 1: Proof successfully created.
//           0: Error
// 	 In:     ctx:    pointer to a context object, initialized for range-proof, signing, and Pedersen commitment (cannot be NULL)
//           proof:  pointer to array to receive the proof, can be up to 5134 bytes. (cannot be NULL)
//           min_value: constructs a proof where the verifer can tell the minimum value is at least the specified amount.
//           commit: the commitment being proved.
//           blind:  32-byte blinding factor used by commit.
//           nonce:  32-byte secret nonce used to initialize the proof (value can be reverse-engineered out of the proof if this secret is known.)
//           exp:    Base-10 exponent. Digits below above will be made public, but the proof will be made smaller. Allowed range is -1 to 18.
//                   (-1 is a special case that makes the value public. 0 is the most private.)
//           min_bits: Number of bits of the value to keep private. (0 = auto/minimal, - 64).
//           value:  Actual value of the commitment.
//           message: pointer to a byte array of data to be embedded in the rangeproof that can be recovered by rewinding the proof
//           extra_commit: additional data to be covered in rangeproof signature
//           gen: additional generator 'h'
//
// If min_value or exp is non-zero then the value must be on the range [0, 2^63) to prevent the proof range from spanning past 2^64.
//
// If exp is -1 the value is revealed by the proof (e.g. it proves that the proof is a blinding of a specific value, without revealing the blinding key.)
//
// This can randomly fail with probability around one in 2^100. If this happens, buy a lottery ticket and retry with a different nonce or blinding.
/*
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
func RangeProofSign(
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
	var cproof [MaxRangeProofSize]byte
	var cprooflen C.size_t = MaxRangeProofSize

	if 1 != C.secp256k1_rangeproof_sign(
		context.ctx,
		cBuf(cproof[:]),
		&cprooflen,
		C.uint64_t(minValue),
		commit.com,
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
		err = errors.New(ErrRangeProof)
	} else {
		proof = cproof[:int(cprooflen)]
	}

	return
}

// RangeProofInfo extracts some basic information from a range-proof.
//
// 	 Returns 1: Information successfully extracted.
//         	 0: Decode failed.
// 	 In:   	 ctx: pointer to a context object
//       	 	 proof: pointer to character array with the proof.
// 	 Out:  	 exp: Exponent used in the proof (-1 means the value isn't private).
//       	 	 mantissa: Number of bits covered by the proof.
//       	 	 min_value: pointer to an unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
//       	 	 max_value: pointer to an unsigned int64 which will be updated with the maximum value that commit could have. (cannot be NULL)
func RangeProofInfo(
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
		err = errors.New(ErrRangeProofInfo)
		return
	}

	return
}

// RangeProofVerify verifies a proof that a committed value is within a range.
// 	 Returns 1: Value is within the range [0..2^64), the specifically proven range is in the min/max value outputs.
//         	 0: Proof failed or other error.
// 	 In:   	 ctx: pointer to a context object, initialized for range-proof and commitment (cannot be NULL)
//       	 	 commit: the commitment being proved. (cannot be NULL)
//       	 	 proof: pointer to character array with the proof. (cannot be NULL)
//      	 	 extra_commit: additional data covered in rangeproof signature
//       	 	 gen: additional generator 'h'
// 	 Out:  	 min_value: pointer to a unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
//       	 	 max_value: pointer to a unsigned int64 which will be updated with the maximum value that commit could have. (cannot be NULL)
/*
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
func RangeProofVerify(
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
		commit.com,
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

// RangeProofRewind verifies a range proof and rewind the proof to recover information sent by its author.
//	 Returns 1: Value is within the range [0..2^64), the specifically proven range is in the min/max value outputs, and the value and blinding were recovered.
//           0: Proof failed, rewind failed, or other error.
//	 In:   	 ctx: pointer to a context object, initialized for range-proof and Pedersen commitment (cannot be NULL)
//        	 commit: the commitment being proved. (cannot be NULL)
//        	 proof: pointer to character array with the proof. (cannot be NULL)
//        	 nonce: 32-byte secret nonce used by the prover (cannot be NULL)
//        	 extra_commit: additional data covered in rangeproof signature
//        	 gen: additional generator 'h'
// 	 In/Out: blind_out: storage for the 32-byte blinding factor used for the commitment
//        	 value_out: pointer to an unsigned int64 which has the exact value of the commitment.
//        	 message_out: pointer to a 4096 byte character array to receive message data from the proof author.
//        	 outlen:  length of message data written to message_out.
//        	 min_value: pointer to an unsigned int64 which will be updated with the minimum value that commit could have. (cannot be NULL)
//        	 max_value: pointer to an unsigned int64 which will be updated with the maximum value that commit could have. (cannot be NULL)
/*
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
func RangeProofRewind(
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
		commit.com,
		cBuf(proof),
		(C.size_t)(len(proof)),
		cExtraCmt,
		C.size_t(cExtraCmtLen),
		gen.gen,
	) {
		err = errors.New(ErrRangeProofRewind)
		return
	}
	message = make([]byte, msgLen)
	copy(message, msg[:msgLen])

	return
}
