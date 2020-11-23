package secp256k1

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"

)

func TestSurjectionLoop(t *testing.T) {
	for i := 0; i < 1; i++ {
		TestSurjectionAPI(t)
	}
}

func TestSurjectionAPI(t *testing.T) {
	for it := 0; it < 100; it++ {

		var (
			fixedInputTags [10]*FixedAssetTag
			// fixedOutputTag     FixedAssetTag
			ephemeralInputTags []*Generator
			ephemeralOutputTag *Generator
			inputBlindingKeys  [10][32]byte
			outputBlindingKey  [32]byte
			//serializedProof    [SurjectionproofSerializationBytesMax]byte
			//serializedLen      int
			//proof              Surjectionproof
			proof       Surjectionproof
			nInputs     = len(fixedInputTags)
			nIterations int
			inputIndex  int
			outputIndex int = 3

			seed [32]byte = Random256()
			// callbackHanderFunc ContextCallbackFunc = func(msg string) { eCount++ }
		)
		//none, _ := ContextCreate(ContextNone)
		//sign, _ := ContextCreate(ContextSign)
		//vrfy, _ := ContextCreate(ContextVerify)
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
			fixedInputTags[i] = assetTag
			inputBlindingKeys[i] = assetBlind
			ephemeralInputTags = append(ephemeralInputTags, assetGenerator)
		}
		outputBlindingKey = Random256()
		tmp, _ := FixedAssetTagSerialize(fixedInputTags[outputIndex])
		outputAsset, _ := FixedAssetTagParse(tmp[:])
		outputGenerator, _ := GeneratorGenerateBlinded(both, outputAsset.Slice(), outputBlindingKey[:])
		// fixedOutputTag := *outputAsset
		ephemeralOutputTag = outputGenerator

		var err error

		// check allocate_initialized
		/*	nIterations, proof, inputIndex, err = SurjectionproofAllocateInitialized(none, fixedInputTags[:], 0, &fixedInputTags[0], 100, seed[:])
			assert.Error(t, err)
			assert.Empty(t, proof)
			nIterations, proof, inputIndex, err = SurjectionproofAllocateInitialized(none, fixedInputTags[:], 3, &fixedInputTags[0], 100, seed[:])
			assert.NoError(t, err)
			assert.NotEmpty(t, proof)
			SurjectionproofDestroy(proof)

			nIterations, proof, inputIndex, err = SurjectionproofAllocateInitialized(none, fixedInputTags[:], 3, &fixedInputTags[0], 100, seed[:])
			assert.NoError(t, err)
		*/
		proof, inputIndex, err = SurjectionproofInitialize(both, fixedInputTags[:], 2, fixedInputTags[outputIndex], 100, seed[:])
		assert.NoError(t, err)

		//proofBytes, _ := SurjectionproofSerialize(none, proof)
		fmt.Printf("#%d initialized: outtag=%v, numiter=%v, inpidx=%d, verified=%v\n", it, ephemeralOutputTag.String(), nIterations, inputIndex, err == nil)

		// check generate
		err = SurjectionproofGenerate(both, proof, ephemeralInputTags, ephemeralOutputTag, inputIndex, inputBlindingKeys[outputIndex][:], outputBlindingKey[:])
		assert.NoError(t, err)

		proofBytes, err := SurjectionproofSerialize(SharedContext(ContextNone), &proof)
		assert.NoError(t, err)

		proof2, err := SurjectionproofParse(SharedContext(ContextNone), proofBytes)
		assert.NoError(t, err)
		assert.Equal(t, proof, proof2)

		// check verify
		err = SurjectionproofVerify(both, proof, ephemeralInputTags, ephemeralOutputTag)

		fmt.Printf("#%d: verified=%v, proof=%X\n", it, err, proofBytes)
		assert.NoError(t, err)

	}
	/*
	   CHECK(secp256k1_surjectionooproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 0, &fixed_input_tags[0], 100, seed) == 0);
	   CHECK(proof_on_heap == 0);
	   CHECK(ecount == 0);
	   CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 3, &fixed_input_tags[0], 100, seed) != 0);
	   CHECK(proof_on_heap != 0);
	   secp256k1_surjectionproof_destroy(prf_on_heap);
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

func TestSurjectionGenVerifyLoop(t *testing.T) {
	for i := 0; i < 1; i++ {
		fmt.Printf("#%v: ", i)
		TestSurjectionproofGenVerify(t)
	}
}

func TestSurjectionproofGenVerify(t *testing.T) {

	const nUsed = 3
	const nInputs = 10
	const nInputsMax = 10

	for it := 0; it < 100; it++ {

		var inpAssets [nInputsMax]*FixedAssetTag
		var inpEphems [nInputsMax]*Generator
		var inpBlinds [nInputsMax][32]byte
		var outAsset *FixedAssetTag
		var outEphem *Generator
		var outBlind [32]byte
		var err error

		//seed := [32]byte{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1} //Random256()
		keyIndex := it % nInputs // <-sequental vs random-> ((int(seed[0]) << 16) + (int(seed[1]) << 8) + int(seed[2])) % nInputs
		assert.LessOrEqual(t, nUsed, nInputs)
		assert.LessOrEqual(t, nInputs, nInputsMax)
		assert.Less(t, keyIndex, nInputs)

		for i := 0; i < nInputs; i++ {
			// choose random fixed tag, except that for the output one copy from the key_index
			tagid := RandomScalarOrder256()
			inpAssets[i], err = FixedAssetTagParse(tagid[:])
			assert.NoError(t, err)
			//tagbytes, err := FixedAssetTagSerialize(inpAssets[i])
			//assert.NoError(t, err)
			//fmt.Printf("\n%x", tagbytes)
		}
		outAsset, err = FixedAssetTagParse(inpAssets[keyIndex].Slice())
		assert.NoError(t, err)

		for itx := 0; itx < 100; itx++ {

			for i := 0; i < nInputs; i++ {
				//input_blindings[i] = Random256()
				blind := RandomScalarOrder256()
				//rand32, err := AggsigGenerateSecureNonce(SharedContext(ContextBoth), seed32[:])
				//assert.NoError(t, err)
				copy(inpBlinds[i][:], blind[:])

				//fmt.Printf("\nblind %d: %x", i, inpBlinds[i][:])

				ephem, err := GeneratorGenerateBlinded(SharedContext(ContextBoth), inpAssets[i].Slice(), inpBlinds[i][:])
				assert.NoError(t, err)
				inpEphems[i] = ephem
				//fmt.Printf(", ephem %d: %s", i, ephem)
			}

			outBlind = RandomScalarOrder256()
			outEphem, err = GeneratorGenerateBlinded(SharedContext(ContextBoth), outAsset.Slice(), outBlind[:])
			assert.NoError(t, err)

			nIters, proof, inputIndex, err := SurjectionproofAllocateInitialized(SharedContext(ContextBoth), inpAssets[:], nUsed, outAsset, 100, nil)
			assert.NoError(t, err)
			if nUsed == 0 {
				assert.True(t, nIters == 0)
				return
			}
			assert.True(t, nIters > 0)
			assert.True(t, inputIndex == keyIndex)

			err = SurjectionproofGenerate(SharedContext(ContextBoth), proof, inpEphems[:], outEphem, inputIndex, inpBlinds[inputIndex][:], outBlind[:])
			assert.NoError(t, err)

			serializedProof, err := SurjectionproofSerialize(SharedContext(ContextBoth), &proof)
			assert.NoError(t, err)

			deserializedProof, err := SurjectionproofParse(SharedContext(ContextBoth), serializedProof)
			assert.NoError(t, err)
			assert.Equal(t, proof, deserializedProof)

			err = SurjectionproofVerify(SharedContext(ContextVerify), deserializedProof, inpEphems[:], outEphem)
			if err == nil {
				fmt.Printf("PASS ")
			} else {
				fmt.Printf("FAIL ")
			}
			//fmt.Printf(" :: %d :: SurjectionproofVerify :: tid=%X/%X, proof=%X\n", it, GetThreadId(), GetThreadId64(), serializedProof)
			if err == nil {
				break
			}
			assert.NoError(t, err)
		}
		//assert.NoError(t, verified)
	}
	/*
		static void test_gen_verify(size_t n_inputs, size_t n_used) {
			unsigned char seed[32];
			secp256k1_surjectionproof proof;
			unsigned char serialized_proof[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX];
			unsigned char serialized_proof_trailing[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX + 1];
			size_t serialized_len = SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX;
			secp256k1_fixed_asset_tag fixed_input_tags[1000];
			secp256k1_generator ephemeral_input_tags[1000];
			unsigned char *input_blinding_key[1000];
			const size_t max_n_inputs = sizeof(fixed_input_tags) / sizeof(fixed_input_tags[0]) - 1;
			size_t try_count = n_inputs * 100;
			size_t key_index;
			size_t input_index;
			size_t i;
			int result;

		    // setup
			CHECK(n_used <= n_inputs);
			CHECK(n_inputs < max_n_inputs);
			secp256k1_rand256(seed);

			key_index = (((size_t) seed[0] << 8) + seed[1]) % n_inputs;

			for (i = 0; i < n_inputs + 1; i++) {
				input_blinding_key[i] = malloc(32);
				secp256k1_rand256(input_blinding_key[i]);
				// choose random fixed tag, except that for the output one copy from the key_index
				if (i < n_inputs) {
					secp256k1_rand256(fixed_input_tags[i].data);
				} else {
					memcpy(&fixed_input_tags[i], &fixed_input_tags[key_index], sizeof(fixed_input_tags[i]));
				}
				CHECK(secp256k1_generator_generate_blinded(ctx, &ephemeral_input_tags[i], fixed_input_tags[i].data, input_blinding_key[i]));
			}

			// test
			result = secp256k1_surjectionproof_initialize(ctx, &proof, &input_index, fixed_input_tags, n_inputs, n_used, &fixed_input_tags[key_index], try_count, seed);
			if (n_used == 0) {
				CHECK(result == 0);
				return;
			}
			CHECK(result > 0);
			CHECK(input_index == key_index);

			result = secp256k1_surjectionproof_generate(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs], input_index, input_blinding_key[input_index], input_blinding_key[n_inputs]);
			CHECK(result == 1);

			CHECK(secp256k1_surjectionproof_serialize(ctx, serialized_proof, &serialized_len, &proof));
			CHECK(serialized_len == secp256k1_surjectionproof_serialized_size(ctx, &proof));
			CHECK(serialized_len == SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(n_inputs, n_used));

			// trailing garbage
			memcpy(&serialized_proof_trailing, &serialized_proof, serialized_len);
			serialized_proof_trailing[serialized_len] = seed[0];
			CHECK(secp256k1_surjectionproof_parse(ctx, &proof, serialized_proof_trailing, serialized_len + 1) == 0);

			CHECK(secp256k1_surjectionproof_parse(ctx, &proof, serialized_proof, serialized_len));
			result = secp256k1_surjectionproof_verify(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs]);
			CHECK(result == 1);

			// various fail cases
			if (n_inputs > 1) {
				result = secp256k1_surjectionproof_verify(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs - 1]);
				CHECK(result == 0);

				// number of entries in ephemeral_input_tags array is less than proof.n_inputs
				n_inputs -= 1;
				result = secp256k1_surjectionproof_generate(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs], input_index, input_blinding_key[input_index], input_blinding_key[n_inputs]);
				CHECK(result == 0);
				result = secp256k1_surjectionproof_verify(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs - 1]);
				CHECK(result == 0);
				n_inputs += 1;
			}

			for (i = 0; i < n_inputs; i++) {
				// flip bit
				proof.used_inputs[i / 8] ^= (1 << (i % 8));
				result = secp256k1_surjectionproof_verify(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs]);
				CHECK(result == 0);
				// reset the bit
				proof.used_inputs[i / 8] ^= (1 << (i % 8));
			}

			// cleanup
			for (i = 0; i < n_inputs + 1; i++) {
				free(input_blinding_key[i]);
			}
		}
	*/
}

func TestSurjectionproofInitializeAndSerialize(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/surjectionproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["initializeAndSerialize"].([]interface{})

	ctx, _ := ContextCreate(ContextNone)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		seed, _ := hex.DecodeString(v["seed"].(string))
		nInputTagsToUse := int(v["inputTagsToUse"].(float64))
		nMaxIterations := int(v["maxIterations"].(float64))
		fixedOutputTag, err := FixedAssetTagFromHex(v["outputTag"].(string))
		assert.NoError(t, err)
		fixedInputTags := []*FixedAssetTag{}
		for _, inTag := range v["inputTags"].([]interface{}) {
			fixedAssetTag, err := FixedAssetTagFromHex(inTag.(string))
			assert.NoError(t, err)
			fixedInputTags = append(fixedInputTags, fixedAssetTag)
		}

		proof, inputIndex, err := SurjectionproofInitialize(
			ctx,
			fixedInputTags,
			nInputTagsToUse,
			fixedOutputTag,
			nMaxIterations,
			seed,
		)
		assert.NoError(t, err)
		expected := v["expected"].(map[string]interface{})
		assert.Equal(t, int(expected["inputIndex"].(float64)), inputIndex)
		assert.Equal(t, expected["proof"].(string), proof.String())
		assert.Equal(t, int(expected["nInputs"].(float64)), SurjectionproofNTotalInputs(ctx, proof))
		assert.Equal(t, int(expected["nUsedInputs"].(float64)), SurjectionproofNUsedInputs(ctx, proof))
	}
}

func TestSurjectionproofGenerateAndVerify(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/surjectionproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
	vectors := tests["generateAndVerify"].([]interface{})

	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		inIndex := int(v["inputIndex"].(float64))
		inBlindingKey, _ := hex.DecodeString(v["inputBlindingKey"].(string))
		outBlindingKey, _ := hex.DecodeString(v["outputBlindingKey"].(string))
		proof, err := SurjectionproofFromString(v["proof"].(string))
		assert.NoError(t, err)
		ephemeralOutTag, err := GeneratorFromString(v["ephemeralOutputTag"].(string))
		assert.NoError(t, err)
		ephemeralInTags := []*Generator{}
		for _, inTag := range v["ephemeralInputTags"].([]interface{}) {
			ephemeralInTag, err := GeneratorFromString(inTag.(string))
			assert.NoError(t, err)
			ephemeralInTags = append(ephemeralInTags, ephemeralInTag)
		}

		err = SurjectionproofGenerate(
			ctx,
			proof,
			ephemeralInTags,
			ephemeralOutTag,
			inIndex,
			inBlindingKey,
			outBlindingKey,
		)
		assert.NoError(t, err)
		assert.NotNil(t, proof)
		assert.Equal(t, v["expected"].(string), proof.String())
		assert.Equal(t, nil, SurjectionproofVerify(ctx, proof, ephemeralInTags, ephemeralOutTag))
	}
}
