package secp256k1

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestSurjectionLoop(t *testing.T) {
	for i := 0; i < 100; i++ {
		TestSurjectionAPI(t)
	}
}

func TestSurjectionAPI(t *testing.T) {
	for it := 0; it < 1; it++ {

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
		)
		both, _ := ContextCreate(ContextBoth)

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

		nIterations, proof, inputIndex, err = SurjectionproofInitialize(both, fixedInputTags[:], 2, fixedInputTags[outputIndex], 100, seed[:])
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

			nIters, proof, inputIndex, err := SurjectionproofInitialize(SharedContext(ContextBoth), inpAssets[:], nUsed, outAsset, 100, nil)
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
		var fixedInputTags []*FixedAssetTag
		for _, inTag := range v["inputTags"].([]interface{}) {
			fixedAssetTag, err := FixedAssetTagFromHex(inTag.(string))
			assert.NoError(t, err)
			fixedInputTags = append(fixedInputTags, fixedAssetTag)
		}

		nIters, proof, inputIndex, err := SurjectionproofInitialize(
			ctx,
			fixedInputTags,
			nInputTagsToUse,
			fixedOutputTag,
			nMaxIterations,
			seed,
		)
		assert.NoError(t, err)
		assert.NotZero(t, nIters)
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
		var ephemeralInTags []*Generator
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

func TestMaybeValidProof(t *testing.T) {
	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	outputAssets := [][]byte{
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
	}
	outputBfs := [][]byte{
		h2b("06f82730207a7d18f56b67b8232a2183afec39080369b32b83e276017359c329"),
		h2b("06f82730207a7d18f56b67b8232a2183afec39080369b32b83e276017359c329"),
		h2b("b919547b0fe215b1cc259f97ae435d6140d6d68ab62b6ceae216af48a75ed8dd"),
	}

	inputAssets := [][]byte{
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
		h2b("ed167d1b67cf8c72fdc105e7499003a06745e2c42c7d32ed33d3c6dae06a96dd"),
	}
	inputAbfs := [][]byte{
		h2b("11a0828ded4fa0ebcffced49d7e8118ceba3484363486d43ce04fbbb756dfbf9"),
		h2b("25dde14dd92c0594a3765667ad0ba3263298426e5c5cf38148587a9cd3b2f936"),
	}

	proofs := []string{
		"0200033e70e62dc661225a43f244ac54110cf68a855544be210442ca47e91e5580705dc0955a93a957f4a336cfec7df190c7df0c84fe86f31b51cae3ea1877304cd5a85d516a4e921dd3645783cd41fca8d519783a57dc14767946af0d4fa223d65392",
		"0200033e70e62dc661225a43f244ac54110cf68a855544be210442ca47e91e5580705dc0955a93a957f4a336cfec7df190c7df0c84fe86f31b51cae3ea1877304cd5a85d516a4e921dd3645783cd41fca8d519783a57dc14767946af0d4fa223d65392",
		"0200033e8c1bb14b8bb3163102181b7f932515dad5e5ec02e6d32180c04aad77ec8f0ea12653e52cfc8f6d7854c3d671dda156a2dffa750a08f7c4a04b4644559879a46be28a1aa499f8b9068326f3a0bf764b4a8cb67d80f60d0d856118170e5787b4",
	}

	for j := 0; j < 100; j++ {
		ress := make([]bool, 0, len(proofs))
		for i, outputAsset := range outputAssets {
			outputBf := outputBfs[i]

			outputGenerator, err := GeneratorGenerateBlinded(ctx, outputAsset, outputBf)
			if err != nil {
				t.Fatal(err)
			}

			inputGenerators := make([]*Generator, 0, len(inputAssets))
			for i, v := range inputAssets {
				gen, err := GeneratorGenerateBlinded(ctx, v, inputAbfs[i])
				if err != nil {
					t.Fatal(err)
				}
				inputGenerators = append(inputGenerators, gen)
			}

			proof, err := SurjectionproofFromString(proofs[i])
			if err != nil {
				t.Fatal(err)
			}
			res := SurjectionproofVerify(ctx, proof, inputGenerators, outputGenerator)
			ress = append(ress, res == nil)
		}
		fmt.Println(ress)
	}
}

func h2b(str string) []byte {
	buf, _ := hex.DecodeString(str)
	return buf
}

func TestMaybeInvalidProof(t *testing.T) {
	ctx := SharedContext(ContextBoth)

	outputAssets := [][]byte{
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
	}
	outputBfs := [][]byte{
		h2b("06f82730207a7d18f56b67b8232a2183afec39080369b32b83e276017359c329"),
		h2b("06f82730207a7d18f56b67b8232a2183afec39080369b32b83e276017359c329"),
		h2b("b919547b0fe215b1cc259f97ae435d6140d6d68ab62b6ceae216af48a75ed8dd"),
	}

	inputAssets := [][]byte{
		h2b("25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a"),
		h2b("ed167d1b67cf8c72fdc105e7499003a06745e2c42c7d32ed33d3c6dae06a96dd"),
	}
	inputAbfs := [][]byte{
		h2b("11a0828ded4fa0ebcffced49d7e8118ceba3484363486d43ce04fbbb756dfbf9"),
		h2b("25dde14dd92c0594a3765667ad0ba3263298426e5c5cf38148587a9cd3b2f936"),
	}

	proofs := []string{
		"0200033e70e62dc661225a43f244ac54110cf68a855544be210442ca47e91e5580705dc0955a93a957f4a336cfec7df190c7df0c84fe86f31b51cae3ea1877304cd5a85d516a4e921dd3645783cd41fca8d519783a57dc14767946af0d4fa223d65392",
		"0200033e70e62dc661225a43f244ac54110cf68a855544be210442ca47e91e5580705dc0955a93a957f4a336cfec7df190c7df0c84fe86f31b51cae3ea1877304cd5a85d516a4e921dd3645783cd41fca8d519783a57dc14767946af0d4fa223d65392",
		"0200033e8c1bb14b8bb3163102181b7f932515dad5e5ec02e6d32180c04aad77ec8f0ea12653e52cfc8f6d7854c3d671dda156a2dffa750a08f7c4a04b4644559879a46be28a1aa499f8b9068326f3a0bf764b4a8cb67d80f60d0d856118170e5787b4",
	}

	for i, outputAsset := range outputAssets {
		outputBf := outputBfs[i]

		outputGenerator, err := GeneratorGenerateBlinded(ctx, outputAsset, outputBf)
		if err != nil {
			t.Fatal(err)
		}

		inputGenerators := make([]*Generator, 0, len(inputAssets))
		for i, v := range inputAssets {
			gen, err := GeneratorGenerateBlinded(ctx, v, inputAbfs[i])
			if err != nil {
				t.Fatal(err)
			}
			inputGenerators = append(inputGenerators, gen)
		}

		// Changing byte by byte making proofs invalid, then verifying to confirm each time proof is invalid
		proofBytes, _ := hex.DecodeString(proofs[i])
		for i := 0; i < len(proofBytes); i++ {
			if proofBytes[i] < 255 {
				proofBytes[i] = proofBytes[i] + 1
			} else {
				proofBytes[i] = 0
			}

			proof, err := SurjectionproofParse(SharedContext(ContextNone), proofBytes)
			if err == nil {
				res := SurjectionproofVerify(ctx, proof, inputGenerators, outputGenerator)
				if res == nil {
					t.Fatal("False successful verification")
				}
			}
		}
	}
}
