package secp256k1

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSurjectionAPI(t *testing.T) {

	var (
		fixedInputTags [10]FixedAssetTag
		//fixedOutputTag     FixedAssetTag
		ephemeralInputTags [10]Generator
		ephemeralOutputTag Generator
		inputBlindingKeys  [10][32]byte
		outputBlindingKey  [32]byte
		serializedProof    [SurjectionproofSerializationBytesMax]byte
		serializedLen      int
		proof              Surjectionproof
		proofOnHeap        *Surjectionproof
		nInputs            = len(fixedInputTags)
		nIterations        int
		inputIndex         int
		eCount             int

		seed [32]byte = Random256()
		// callbackHanderFunc ContextCallbackFunc = func(msg string) { eCount++ }
	)
	none, _ := ContextCreate(ContextNone)
	sign, _ := ContextCreate(ContextSign)
	vrfy, _ := ContextCreate(ContextVerify)
	both, _ := ContextCreate(ContextBoth)
	// none.ErrorCallback = &callbackHanderFunc
	// sign.ErrorCallback = &callbackHanderFunc
	// vrfy.ErrorCallback = &callbackHanderFunc
	// both.ErrorCallback = &callbackHanderFunc
	// none.IllegalCallback = &callbackHanderFunc
	// sign.IllegalCallback = &callbackHanderFunc
	// vrfy.IllegalCallback = &callbackHanderFunc
	// both.IllegalCallback = &callbackHanderFunc

	// generate test data
	for i := 0; i < nInputs; i++ {
		assetId := Random256()
		assetTag, _ := FixedAssetTagParse(assetId[:])
		assetBlind := Random256()
		assetGenerator, _ := GeneratorGenerateBlinded(both, assetTag.Slice(), assetBlind[:])
		fixedInputTags[i] = *assetTag
		inputBlindingKeys[i] = assetBlind
		ephemeralInputTags[i] = *assetGenerator
	}
	outputBlindingKey = Random256()
	tmp, _ := FixedAssetTagSerialize(&fixedInputTags[0])
	outputAsset, _ := FixedAssetTagParse(tmp[:])
	outputGenerator, _ := GeneratorGenerateBlinded(both, outputAsset.Slice(), outputBlindingKey[:])
	// fixedOutputTag := *outputAsset
	ephemeralOutputTag = *outputGenerator

	var err error
	fmt.Print(ephemeralOutputTag, serializedProof, serializedLen, proof, nIterations, inputIndex, eCount, sign, vrfy)

	// check allocate_initialized
	nIterations, proofOnHeap, inputIndex, err = SurjectionproofAllocateInitialized(none, fixedInputTags[:], 0, &fixedInputTags[0], 100, seed[:])
	assert.Error(t, err)
	assert.Nil(t, proofOnHeap)
	nIterations, proofOnHeap, inputIndex, err = SurjectionproofAllocateInitialized(none, fixedInputTags[:], 3, &fixedInputTags[0], 100, seed[:])
	assert.NoError(t, err)
	assert.NotNil(t, proofOnHeap)
	SurjectionproofDestroy(proofOnHeap)
	nIterations, proofOnHeap, inputIndex, err = SurjectionproofAllocateInitialized(none, fixedInputTags[:], 3, &fixedInputTags[0], 100, seed[:])
	assert.NoError(t, err)

	nIterations, proofOnHeap, inputIndex, err = SurjectionproofAllocateInitialized(none, fixedInputTags[:], 3, &fixedInputTags[0], 100, seed[:])
	assert.NoError(t, err)

	// check generate
	err = SurjectionproofGenerate(both, proofOnHeap, ephemeralInputTags[:], ephemeralOutputTag, 0, inputBlindingKeys[0][:], outputBlindingKey[:])
	assert.NoError(t, err)

	// check verify
	err = SurjectionproofVerify(vrfy, proofOnHeap, ephemeralInputTags[:], ephemeralOutputTag)
	assert.NoError(t, err)

	/*
	   CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 0, &fixed_input_tags[0], 100, seed) == 0);
	   CHECK(proof_on_heap == 0);
	   CHECK(ecount == 0);
	   CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 3, &fixed_input_tags[0], 100, seed) != 0);
	   CHECK(proof_on_heap != 0);
	   secp256k1_surjectionproof_destroy(proof_on_heap);
	   CHECK(ecount == 0);

	   CHECK(secp256k1_surjectionproof_allocate_initialized(none, NULL, &input_index, fixed_input_tags, n_inputs, 3, &fixed_input_tags[0], 100, seed) == 0);
	   CHECK(ecount == 1);
	   CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, NULL, fixed_input_tags, n_inputs, 3, &fixed_input_tags[0], 100, seed) == 0);
	   CHECK(proof_on_heap == 0);
	   CHECK(ecount == 2);
	   CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, NULL, n_inputs, 3, &fixed_input_tags[0], 100, seed) == 0);
	   CHECK(proof_on_heap == 0);
	   CHECK(ecount == 3);
	   CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS + 1, 3, &fixed_input_tags[0], 100, seed) == 0);
	   CHECK(proof_on_heap == 0);
	   CHECK(ecount == 4);
	   CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, n_inputs, &fixed_input_tags[0], 100, seed) != 0);
	   CHECK(proof_on_heap != 0);
	   secp256k1_surjectionproof_destroy(proof_on_heap);
	   CHECK(ecount == 4);
	   CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, n_inputs + 1, &fixed_input_tags[0], 100, seed) == 0);
	   CHECK(proof_on_heap == 0);
	   CHECK(ecount == 5);
	   CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 3, NULL, 100, seed) == 0);
	   CHECK(proof_on_heap == 0);
	   CHECK(ecount == 6);
	   CHECK((secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 0, &fixed_input_tags[0], 0, seed) & 1) == 0);
	   CHECK(proof_on_heap == 0);
	   CHECK(ecount == 6);
	   CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 0, &fixed_input_tags[0], 100, NULL) == 0);
	   CHECK(proof_on_heap == 0);
	   CHECK(ecount == 7);
	*/

}
