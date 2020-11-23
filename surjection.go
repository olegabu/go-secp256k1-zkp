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
    #include <string.h>
    #include "include/secp256k1_surjectionproof.h"
    #include "include/secp256k1_generator.h"
    static int surjectionproofSerializationBytes(int nInputs, int nUsedInputs) { return SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(nInputs, nUsedInputs); }
    static secp256k1_fixed_asset_tag* makeFixedAssetTagsArray(int size) { return !size ? NULL : calloc(sizeof(secp256k1_fixed_asset_tag), size); }
    static int setFixedAssetTagsArray(secp256k1_fixed_asset_tag* a, secp256k1_fixed_asset_tag* v, size_t i) { if (!a || !v) return 0; memcpy((a + i)->data, v->data, sizeof(v->data)); return sizeof(v->data); }
    static void freeFixedAssetTagsArray(secp256k1_fixed_asset_tag* a) { if (a) free(a); }
    static secp256k1_generator** makeGeneratorsArray(int size) { return !size ? NULL : calloc(sizeof(secp256k1_generator*), size); }
    static void setGeneratorsArray(secp256k1_generator** a, secp256k1_generator* v, int i) { if (a) a[i] = v; }
    static secp256k1_generator* getGeneratorsArray(secp256k1_generator** a, int i) { if (a) return a[i]; }
    static void freeGeneratorsArray(secp256k1_generator** a) { if (a) free(a); }
    static size_t* makeSizeArray(int size) { return !size ? NULL : calloc(sizeof(size_t), size); }
    static void setSizeArray(size_t* a, size_t v, int i) { if (a) a[i] = v; }
    static void freeSizeArray(size_t* a) { if (a) free(a); }
    static const unsigned char** makeBytesArray(int size) { return !size ? NULL : calloc(sizeof(unsigned char*), size); }
    static void setBytesArray(unsigned char** a, unsigned char* v, int i) { if (a) a[i] = v; }
    static unsigned char* getBytesArray(unsigned char** a, int i) { return !a ? NULL : a[i]; }
    static void freeBytesArray(unsigned char** a) { if (a) free(a); }
#ifdef USE_REDUCED_SURJECTION_PROOF_SIZE
    static int useReducedSurjectionproofSize = 1;
#else
    static int useReducedSurjectionproofSize = 0;
#endif
    static int asset_from_bytes(secp256k1_fixed_asset_tag* dst, const unsigned char* src) { if (!src || !dst) return 0; memcpy(&dst->data[0], &src[0], 32); return 32; }
    static int asset_to_bytes(unsigned char* dst, const secp256k1_fixed_asset_tag* src) { if (!src || !dst) return 0; memcpy(&dst[0], &src->data[0], 32); return 32; }
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// Maximum number of inputs that may be given in a surjection proof
	SurjectionproofMaxNInputs = C.SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS // = 256

	// Maximum number of inputs that may be used in a surjection proof
	SurjectionproofMaxUsedInputs         = C.SECP256K1_SURJECTIONPROOF_MAX_USED_INPUTS // = 256
	SurjectionproofSerializationBytesMax = C.SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX

	// Error types */
	ErrorSurjectionproofParams       string = "invalid input parameters"
	ErrorSurjectionproofVerification string = "surjectionproof verification failed"
	ErrorSurjectionproofGeneration   string = "surjectionproof generation failed"
)

// Number of bytes a serialized surjection proof requires given the
// number of inputs and the number of used inputs
func SurjectionproofSerializationBytesCalc(nInputs int, nUsedInputs int) int {
	return int(C.surjectionproofSerializationBytes(C.int(nInputs), C.int(nUsedInputs)))
}

/** Opaque data structure that holds a parsed surjection proof
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. Nor is
 *  it guaranteed to have any particular size, nor that identical proofs
 *  will have identical representation. (That is, memcmp may return nonzero
 *  even for identical proofs.)
 *
 *  To obtain these properties, instead use secp256k1_surjectionproof_parse
 *  and secp256k1_surjectionproof_serialize to encode/decode proofs into a
 *  well-defined format.
 *
 *  The representation is exposed to allow creation of these objects on the
 *  stack; please *do not* use these internals directly.
 */
type Surjectionproof struct {
	proof *C.secp256k1_surjectionproof
}

/** Parse a surjection proof
 *
 *  Returns: 1 when the proof could be parsed, 0 otherwise.
 *  Args: ctx:    a secp256k1 context object
 *  Out:  proof:  a pointer to a proof object
 *  In:   input:  a pointer to the array to parse
 *        inputlen: length of the array pointed to by input
 *
 *  The proof must consist of:
 *    - A 2-byte little-endian total input count `n`
 *    - A ceil(n/8)-byte bitmap indicating which inputs are used.
 *    - A big-endian 32-byte borromean signature e0 value
 *    - `m` big-endian 32-byte borromean signature s values, where `m`
 *      is the number of set bits in the bitmap
 */
// SECP256K1_API int secp256k1_surjectionproof_parse(
//     const secp256k1_context* ctx,
//     secp256k1_surjectionproof *proof,
//     const unsigned char *input,
//     size_t inputlen
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);
func SurjectionproofParse(
	context *Context,
	bytes []byte,
) (
	proof Surjectionproof,
	err error,
) {
	proof.proof = &C.secp256k1_surjectionproof{}
	if 1 != C.secp256k1_surjectionproof_parse(
		context.ctx,
		proof.proof,
		cBuf(bytes),
		C.size_t(len(bytes))) {

		err = errors.New("Error parsing bytes as a surjection proof object")
	}

	return
}

func NewSurjectionproof() (proof Surjectionproof) {
	proof.proof = &C.secp256k1_surjectionproof{}
	return
}

/** Serialize a surjection proof
 *
 *  Returns: 1 if enough space was available to serialize, 0 otherwise
 *  Args:   ctx:        a secp256k1 context object
 *  Out:    output:     a pointer to an array to store the serialization
 *  In/Out: outputlen:  a pointer to an integer which is initially set to the
 *                      size of output, and is overwritten with the written
 *                      size.
 *  In:     proof:      a pointer to an initialized proof object
 *
 *  See secp256k1_surjectionproof_parse for details about the encoding.
 */
// SECP256K1_API int secp256k1_surjectionproof_serialize(
// const secp256k1_context* ctx,
//     unsigned char *output,
//     size_t *outputlen,
//     const secp256k1_surjectionproof *proof
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);
func SurjectionproofSerialize(
	context *Context,
	proof *Surjectionproof,
) (
	bytes []byte,
	err error,
) {
	var data [SurjectionproofSerializationBytesMax]C.uchar
	size := C.size_t(len(data))
	if 1 != C.secp256k1_surjectionproof_serialize(
		context.ctx,
		&data[0],
		&size,
		proof.proof,
	) {

		return nil, errors.New("Error serializing a surjection proof object")
	}

	return goBytes(data[:], C.int(size)), nil
}

func (proof *Surjectionproof) Bytes() (bytes []byte) {
	bytes, _ = SurjectionproofSerialize(SharedContext(ContextNone), proof)
	return
}

func (proof *Surjectionproof) String() string {
	bytes := proof.Bytes()

	return hex.EncodeToString(bytes)
}

func SurjectionproofFromString(str string) (proof Surjectionproof, err error) {
	var bytes []byte
	bytes, err = hex.DecodeString(str)
	if err == nil {
		proof, err = SurjectionproofParse(SharedContext(ContextNone), bytes)
	}

	return
}

/** Data structure that holds a fixed asset tag.
 *
 * This data type is *not* opaque. It will always be 32 bytes of whatever
 * data the API user wants to use as an asset tag. Its contents have no
 * semantic meaning to libsecp whatsoever.
 */
// typedef struct { unsigned char data[32]; } secp256k1_fixed_asset_tag;
type FixedAssetTag struct {
	tag *C.secp256k1_fixed_asset_tag
}

func newFixedAssetTag() *FixedAssetTag {
	return &FixedAssetTag{tag: &C.secp256k1_fixed_asset_tag{}}
}

/** Parse a sequence of bytes as a FixedAssetTag
 *
 *  Returns: 1 if input contains a valid FixedAssetTag
 *  In:   data32: pointer to a 33-byte serialized data
 *  Out:  nil/FixedAssetTag
 */
func FixedAssetTagParse(
	data32 []byte,
) (
	*FixedAssetTag,
	error,
) {
	asset := newFixedAssetTag()
	if 0 == C.asset_from_bytes(asset.tag, cBuf(data32)) {
		return nil, errors.New("FixedAssetTagParse error")
	}

	return asset, nil
}

/** Serialize FixedAssetTag into sequence of bytes.
 *
 *  Returns: 1 always.
 *  In:     FixedAssetTag - fixed asset tag object
 *  Out:    serialized data: 32-byte byte array
**/
func FixedAssetTagSerialize(
	asset *FixedAssetTag,
) (
	data [32]byte,
	err error,
) {
	if 0 == C.asset_to_bytes(cBuf(data[:]), asset.tag) {
		err = errors.New("FixedAssetTagSerialize error")
	}

	return
}

func (asset *FixedAssetTag) Bytes() (bytes [32]byte) {
	bytes, _ = FixedAssetTagSerialize(asset)
	return
}

func (asset *FixedAssetTag) Slice() []byte {
	bytes := asset.Bytes()
	return bytes[:]
}

func sliceBytes32(bytes [32]byte) []byte {

	return bytes[:]
}

func (asset *FixedAssetTag) Hex() string {
	bytes := asset.Bytes()

	return hex.EncodeToString(bytes[:])
}

func FixedAssetTagFromHex(str string) (com *FixedAssetTag, err error) {
	bytes, _ := hex.DecodeString(str)
	com, err = FixedAssetTagParse(bytes)

	return
}

/** Returns the total number of inputs a proof expects to be over.
 *
 * Returns: the number of inputs for the given proof
 * In:   ctx: pointer to a context object
 *     proof: a pointer to a proof object
 */
// SECP256K1_API size_t secp256k1_surjectionproof_n_total_inputs(
//     const secp256k1_context* ctx,
//     const secp256k1_surjectionproof* proof
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);
func SurjectionproofNTotalInputs(
	context *Context,
	proof Surjectionproof,
) (
	number int,
) {
	return int(C.secp256k1_surjectionproof_n_total_inputs(
		context.ctx,
		proof.proof,
	))
}

/** Returns the actual number of inputs that a proof uses
 *
 * Returns: the number of inputs for the given proof
 * In:   ctx: pointer to a context object
 *     proof: a pointer to a proof object
 */
// SECP256K1_API size_t secp256k1_surjectionproof_n_used_inputs(
//     const secp256k1_context* ctx,
//     const secp256k1_surjectionproof* proof
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);
func SurjectionproofNUsedInputs(
	context *Context,
	proof Surjectionproof,
) (
	number int,
) {
	return int(C.secp256k1_surjectionproof_n_used_inputs(
		context.ctx,
		proof.proof,
	))
}

/** Returns the total size this proof would take, in bytes, when serialized
 *
 * Returns: the total size
 * In:   ctx: pointer to a context object
 *     proof: a pointer to a proof object
 */
// SECP256K1_API size_t secp256k1_surjectionproof_serialized_size(
//     const secp256k1_context* ctx,
//     const secp256k1_surjectionproof* proof
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);
func SurjectionproofSerializedSize(
	context *Context,
	proof Surjectionproof,
) (
	size int,
) {
	return int(C.secp256k1_surjectionproof_serialized_size(
		context.ctx,
		proof.proof,
	))
}

/** Surjection proof initialization function; decides on inputs to use
 *  To be used to initialize stack-allocated secp256k1_surjectionproof struct
 * Returns 0: inputs could not be selected
 *         n: inputs were selected after n iterations of random selection
 *
 * In:               ctx: pointer to a context object
 *      fixed_input_tags: fixed input tags `A_i` for all inputs. (If the fixed tag is not known,
 *                        e.g. in a coinjoin with others' inputs, an ephemeral tag can be given;
 *                        this won't match the output tag but might be used in the anonymity set.)
 *          n_input_tags: the number of entries in the fixed_input_tags array
 *   n_input_tags_to_use: the number of inputs to select randomly to put in the anonymity set
 *                        Must be <= SECP256K1_SURJECTIONPROOF_MAX_USED_INPUTS
 *      fixed_output_tag: fixed output tag
 *      max_n_iterations: the maximum number of iterations to do before giving up. Because the
 *                        maximum number of inputs (SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS) is
 *                        limited to 256 the probability of giving up is smaller than
 *                        (255/256)^(n_input_tags_to_use*max_n_iterations).
 *
 *         random_seed32: a random seed to be used for input selection
 * Out:            proof: The proof whose bitvector will be initialized. In case of failure,
 *                        the state of the proof is undefined.
 *          input_index: The index of the actual input that is secretly mapped to the output
 */
// SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_surjectionproof_initialize(
//     const secp256k1_context* ctx,
//     secp256k1_surjectionproof* proof,
//     size_t *input_index,
//     const secp256k1_fixed_asset_tag* fixed_input_tags,
//     const size_t n_input_tags,
//     const size_t n_input_tags_to_use,
//     const secp256k1_fixed_asset_tag* fixed_output_tag,
//     const size_t n_max_iterations,
//     const unsigned char *random_seed32
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(7);
func SurjectionproofInitializeNum(
	context *Context,
	fixedInputTags []*FixedAssetTag,
	nInputs int,
	nInputTagsToUse int,
	fixedOutputTag *FixedAssetTag,
	nMaxIterations int,
	seed32 []byte,
) (
	proof Surjectionproof,
	inputIndex int,
	err error,
) {
	if nInputs > len(fixedInputTags) {
		err = errors.New("nInputs exceeds number of elements in the array")
		return
	}
	// cache data locally to prevent unexpected modifications
	data := make([]C.secp256k1_fixed_asset_tag, nInputs)
	ptrs := make([]*C.secp256k1_fixed_asset_tag, nInputs)
	for i := 0; i < nInputs; i++ {
		e := fixedInputTags[i]
		if e == nil || e.tag == nil {
			err = errors.New("input data item is empty")
			return
		}
		data[i] = *(e.tag)
		ptrs[i] = &data[i]
	}

	if seed32 == nil {
		seed := Random256()
		seed32 = seed[:]
	}

	var index C.size_t
	proof.proof = &C.secp256k1_surjectionproof{}
	nIters := int(C.secp256k1_surjectionproof_initialize(
		context.ctx,
		proof.proof,
		&index,
		ptrs[0],
		C.size_t(nInputs),
		C.size_t(nInputTagsToUse),
		fixedOutputTag.tag,
		C.size_t(nMaxIterations),
		cBuf(seed32),
	))
	if nIters <= 0 {
		err = fmt.Errorf("surjection proof initialization failed (%v)", nIters)
	} else {
		inputIndex = int(index)
	}

	return
}

// Wrapper for backward compatibility
// - length of fixedInputTags slice is the nInputs
func SurjectionproofInitialize(
	context *Context,
	fixedInputTags []*FixedAssetTag,
	nInputTagsToUse int,
	fixedOutputTag *FixedAssetTag,
	nMaxIterations int,
	seed32 []byte,
) (
	proof Surjectionproof,
	inputIndex int,
	err error,
) {
	return SurjectionproofInitializeNum(
		context,
		fixedInputTags,
		len(fixedInputTags),
		nInputTagsToUse,
		fixedOutputTag,
		nMaxIterations,
		seed32,
	)
}

/** Surjection proof allocation and initialization function; decides on inputs to use
 * Returns 0: inputs could not be selected, or malloc failure
 *         n: inputs were selected after n iterations of random selection
 *
 * In:               ctx: pointer to a context object
 *           proof_out_p: a pointer to a pointer to `secp256k1_surjectionproof*`.
 *                        the newly-allocated struct pointer will be saved here.
 *      fixed_input_tags: fixed input tags `A_i` for all inputs. (If the fixed tag is not known,
 *                        e.g. in a coinjoin with others' inputs, an ephemeral tag can be given;
 *                        this won't match the output tag but might be used in the anonymity set.)
 *          n_input_tags: the number of entries in the fixed_input_tags array
 *      n_input_tags_to_use: the number of inputs to select randomly to put in the anonymity set
 *      fixed_output_tag: fixed output tag
 *      max_n_iterations: the maximum number of iterations to do before giving up. Because the
 *                        maximum number of inputs (SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS) is
 *                        limited to 256 the probability of giving up is smaller than
 *                        (255/256)^(n_input_tags_to_use*max_n_iterations).
 *
 *         random_seed32: a random seed to be used for input selection
 * Out:      proof_out_p: The pointer to newly-allocated proof whose bitvector will be initialized.
 *                        In case of failure, the pointer will be NULL.
 *          input_index: The index of the actual input that is secretly mapped to the output
 */
// SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_surjectionproof_allocate_initialized(
//     const secp256k1_context* ctx,
//     secp256k1_surjectionproof** proof_out_p,
//     size_t *input_index,
//     const secp256k1_fixed_asset_tag* fixed_input_tags,
//     const size_t n_input_tags,
//     const size_t n_input_tags_to_
//     const secp256k1_fixed_asset_tag* fixed_output_tag,
//     const size_t n_max_iterations,
//     const unsigned char *random_seed32
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(7);
func SurjectionproofAllocateInitialized(
	context *Context,
	fixedInputTags []*FixedAssetTag,
	nInputTagsToUse int,
	fixedOutputTag *FixedAssetTag,
	nMaxIterations int,
	seed32 []byte,
) (
	nIterations int,
	proof Surjectionproof,
	inputIndex int,
	err error,
) {
	// default number of inputs is length of fixedInputTags array, this wrapper is for backward compatibility
	return SurjectionproofAllocateInitializedNum(
		context,
		fixedInputTags,
		len(fixedInputTags),
		nInputTagsToUse,
		fixedOutputTag,
		nMaxIterations,
		seed32,
	)
}
func SurjectionproofAllocateInitializedNum(
	context *Context,
	fixedInputTags []*FixedAssetTag,
	nInputs int,
	nInputTagsToUse int,
	fixedOutputTag *FixedAssetTag,
	nMaxIterations int,
	seed32 []byte,
) (
	nIterations int,
	proof Surjectionproof,
	inputIndex int,
	err error,
) {
	/*tags := C.makeFixedAssetTagsArray(C.int(len(fixedInputTags)))
	defer C.freeFixedAssetTagsArray(tags)
	for idx, asset := range fixedInputTags {
		if idx >= nInputs {
			break
		}
		C.setFixedAssetTagsArray(tags, asset.tag, C.size_t(idx))
	}*/
	if nInputs > len(fixedInputTags) {
		err = errors.New("nInputs exceeds number of elements in the array")
		return
	}
	// cache data locally to prevent unexpected modifications
	data := make([]C.secp256k1_fixed_asset_tag, nInputs)
	ptrs := make([]*C.secp256k1_fixed_asset_tag, nInputs)
	for i := 0; i < nInputs; i++ {
		e := fixedInputTags[i]
		if e == nil || e.tag == nil {
			err = errors.New("input data item is empty")
			return
		}
		data[i] = *(e.tag)
		ptrs[i] = &data[i]
	}

	if seed32 == nil {
		seed := Random256()
		seed32 = seed[:]
	}

	inputindex := C.size_t(0)
	//proof := Surjectionproof{}
	nIters := int(C.secp256k1_surjectionproof_allocate_initialized(
		context.ctx,
		&proof.proof,
		&inputindex,
		ptrs[0],
		C.size_t(nInputs), //len(fixedInputTags)),
		C.size_t(nInputTagsToUse),
		fixedOutputTag.tag,
		C.size_t(nMaxIterations),
		cBuf(seed32),
	))
	if nIters <= 0 {
		err = errors.New("surjection proof allocation/initialization failed")
		return
	}

	return nIters, proof, int(inputindex), nil
}

/** Surjection proof generation function
 * Returns 0: proof could not be created
 *         1: proof was successfully created
 *
 * In:                   ctx: pointer to a context object, initialized for signing and verification
 *      ephemeral_input_tags: the ephemeral asset tag of all inputs
 *    n_ephemeral_input_tags: the number of entries in the ephemeral_input_tags array
 *      ephemeral_output_tag: the ephemeral asset tag of the output
 *               input_index: the index of the input that actually maps to the output
 *        input_blinding_key: the blinding key of the input
 *       output_blinding_key: the blinding key of the output
 * In/Out: proof: The produced surjection proof. Must have already gone through `secp256k1_surjectionproof_initialize`
 */
// SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_surjectionproof_generate(
//     const secp256k1_context* ctx,
//     secp256k1_surjectionproof* proof,
//     const secp256k1_generator* ephemeral_input_tags,
//     size_t n_ephemeral_input_tags,
//     const secp256k1_generator* ephemeral_output_tag,
//     size_t input_index,
//     const unsigned char *input_blinding_key,
//     const unsigned char *output_blinding_key
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);
func SurjectionproofGenerate(context *Context,
	proof Surjectionproof,
	ephemeralInputTags []*Generator,
	ephemeralOutputTag *Generator,
	inputIndex int,
	inputBlindingKey []byte,
	outputBlindingKey []byte,
) (
	err error,
) {
	return SurjectionproofGenerateNum(
		context,
		proof,
		ephemeralInputTags,
		len(ephemeralInputTags),
		ephemeralOutputTag,
		inputIndex,
		inputBlindingKey,
		outputBlindingKey,
	)
}
func SurjectionproofGenerateNum(
	context *Context,
	proof Surjectionproof,
	ephemeralInputTags []*Generator,
	nInputs int,
	ephemeralOutputTag *Generator,
	inputIndex int,
	inputBlindingKey []byte,
	outputBlindingKey []byte,
) (
	err error,
) {
	if nInputs > len(ephemeralInputTags) {
		return errors.New("nInputs exceeds number of elements in the array")
	}
	data := make([]C.secp256k1_generator, nInputs)
	ptrs := make([]*C.secp256k1_generator, nInputs)
	for i := 0; i < nInputs; i++ {
		/*tag := ephemeralInputTags[i]
		if tag == nil || tag.gen == nil {
			return errors.New("SurjectionproofGenerate: empty input tag")
		}
		var tagbytes [33]C.uchar
		C.secp256k1_generator_serialize(context.ctx, &tagbytes[0], tag.gen)
		goptrs[i] = &gotags[i]//C.secp256k1_generator{}
		C.secp256k1_generator_parse(context.ctx, goptrs[i], &tagbytes[0])*/
		// cache data locally to prevent unexpected modifications
		e := ephemeralInputTags[i]
		if e == nil || e.gen == nil {
			return errors.New("input data item is empty")
		}
		data[i] = *(e.gen)
		ptrs[i] = &data[i]
	}

	/*tags := C.makeGeneratorsArray(C.int(len(ephemeralInputTags)))
	defer C.freeGeneratorsArray(tags)
	for idx, tag := range ephemeralInputTags {
		if idx >= nInputs {
			break
		}
		C.setGeneratorsArray(tags, tag.gen, C.int(idx))
	}*/

	status := C.secp256k1_surjectionproof_generate(
		context.ctx,
		proof.proof,
		ptrs[0],
		C.size_t(nInputs), //len(ephemeralInputTags)),
		ephemeralOutputTag.gen,
		C.size_t(inputIndex),
		cBuf(inputBlindingKey),
		cBuf(outputBlindingKey),
	)
	if status != 1 {
		err = fmt.Errorf("surjection proof generation failed (%v)", status)
	}
	return
}

/** Surjection proof verification function
1 * Returns 0: proof was invalid
 *         1: proof was valid
 *
 * In:     ctx: pointer to a context object, initialized for signing and verification
 *         proof: proof to be verified
 *      ephemeral_input_tags: the ephemeral asset tag of all inputs
 *    n_ephemeral_input_tags: the number of entries in the ephemeral_input_tags array
 *      ephemeral_output_tag: the ephemeral asset tag of the output
*/
// SECP256K1_API int secp256k1_surjectionproof_verify(
//     const secp256k1_context* ctx,
//     const secp256k1_surjectionproof* proof,
//     const secp256k1_generator* ephemeral_input_tags,
//     size_t n_ephemeral_input_tags,
//     const secp256k1_generator* ephemeral_output_tag
// ) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5);
func SurjectionproofVerify(
	context *Context,
	proof Surjectionproof,
	ephemeralInputTags []*Generator,
	ephemeralOutputTag *Generator,
) (
	err error,
) {
	return SurjectionproofVerifyNum(
		context,
		proof,
		ephemeralInputTags,
		len(ephemeralInputTags),
		ephemeralOutputTag,
	)
}
func SurjectionproofVerifyNum(
	context *Context,
	proof Surjectionproof,
	ephemeralInputTags []*Generator,
	nInputs int,
	ephemeralOutputTag *Generator,
) (
	err error,
) {
	if nInputs > len(ephemeralInputTags) {
		return errors.New("nInputs exceeds number of elements in the array")
	}
	// cache data locally to prevent unexpected modifications
	data := make([]C.secp256k1_generator, nInputs)
	ptrs := make([]*C.secp256k1_generator, nInputs)
	for i := 0; i < nInputs; i++ {
		e := ephemeralInputTags[i]
		if e == nil || e.gen == nil {
			return errors.New("input data item is empty")
		}
		data[i] = *(e.gen)
		ptrs[i] = &data[i]
	}
	status := C.secp256k1_surjectionproof_verify(
		context.ctx,
		proof.proof,
		ptrs[0],
		C.size_t(nInputs), //len(ephemeralInputTags)),
		ephemeralOutputTag.gen)
	if status != 1 {
		err = fmt.Errorf("surjection proof verification failed (%v)", status)
	}
	return
}
