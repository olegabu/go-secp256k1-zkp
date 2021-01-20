package secp256k1

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRangeproofSign(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/rangeproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	assert.NoError(t, json.Unmarshal(file, &tests))
	vectors := tests["sign"].([]interface{})

	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		value, _ := strconv.Atoi(v["value"].(string))
		minValue, _ := strconv.Atoi(v["minValue"].(string))
		blind, _ := hex.DecodeString(v["blind"].(string))
		nonce, _ := hex.DecodeString(v["commit"].(string))
		commit, err := CommitmentFromString(v["commit"].(string))
		assert.NoError(t, err)
		gen, err := GeneratorFromString(v["generator"].(string))
		assert.NoError(t, err)
		message, _ := hex.DecodeString(v["message"].(string))
		extraCommit, _ := hex.DecodeString(v["extraCommit"].(string))

		proof, err := RangeproofSign(ctx, uint64(minValue), commit, blind, nonce, 0, 0, uint64(value), message, extraCommit, gen)
		assert.NoError(t, err)
		assert.NotNil(t, proof)
		assert.Equal(t, v["expected"].(string), hex.EncodeToString(proof))
	}
}

func TestRangeproofInfo(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/rangeproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	assert.NoError(t, json.Unmarshal(file, &tests))
	vectors := tests["info"].([]interface{})

	ctx, _ := ContextCreate(ContextNone)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		proof, _ := hex.DecodeString(v["proof"].(string))
		expected := v["expected"].(map[string]interface{})
		expectedExp := int(expected["exp"].(float64))
		expectedMantissa := int(expected["mantissa"].(float64))
		expectedMinValue, _ := strconv.Atoi(expected["minValue"].(string))
		expectedMaxValue, _ := strconv.Atoi(expected["maxValue"].(string))

		exp, mantissa, minValue, maxValue, err := RangeproofInfo(ctx, proof)
		assert.NoError(t, err)
		assert.Equal(t, expectedExp, exp)
		assert.Equal(t, expectedMantissa, mantissa)
		assert.Equal(t, uint64(expectedMinValue), minValue)
		assert.Equal(t, uint64(expectedMaxValue), maxValue)
	}
}

func TestRangeproofVerify(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/rangeproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	assert.NoError(t, json.Unmarshal(file, &tests))
	vectors := tests["verify"].([]interface{})

	ctx, _ := ContextCreate(ContextVerify)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		proof, _ := hex.DecodeString(v["proof"].(string))
		extraCommit, _ := hex.DecodeString(v["extraCommit"].(string))
		commit, err := CommitmentFromString(v["commit"].(string))
		assert.NoError(t, err)
		generator, err := GeneratorFromString(v["generator"].(string))
		assert.NoError(t, err)

		assert.Equal(
			t,
			v["expected"].(bool),
			RangeproofVerify(ctx, proof, commit, extraCommit, generator),
		)
	}
}

func TestRangeproofRewind(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/rangeproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	assert.NoError(t, json.Unmarshal(file, &tests))
	vectors := tests["rewind"].([]interface{})

	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	for _, testVector := range vectors {
		v := testVector.(map[string]interface{})

		proof, _ := hex.DecodeString(v["proof"].(string))
		extraCommit, _ := hex.DecodeString(v["extraCommit"].(string))
		buf, _ := hex.DecodeString(v["commit"].(string))
		var nonce [32]byte
		copy(nonce[:], buf)
		commit, err := CommitmentFromString(v["commit"].(string))
		assert.NoError(t, err)
		generator, err := GeneratorFromString(v["generator"].(string))
		assert.NoError(t, err)

		blindingFactor, value, minValue, maxValue, message, err :=
			RangeproofRewind(ctx, commit, proof, nonce, extraCommit, generator)
		assert.NoError(t, err)
		expected := v["expected"].(map[string]interface{})
		assert.Equal(t, expected["value"], strconv.Itoa(int(value)))
		assert.Equal(t, expected["minValue"], strconv.Itoa(int(minValue)))
		assert.Equal(t, expected["maxValue"], strconv.Itoa(int(maxValue)))
		assert.Equal(t, expected["blindFactor"], hex.EncodeToString(blindingFactor[:]))
		assert.Equal(t, expected["message"].(string), hex.EncodeToString(message[:]))
	}
}

func TestRangeproofSingle(t *testing.T) {
	context, err := ContextCreate(ContextVerify | ContextSign)
	assert.NoError(t, err)

	// scratch, err := ScratchSpaceCreate(context, 1024*4096)
	// if err != nil {
	//     return
	// }
	// defer ScratchSpaceDestroy(scratch)

	// generators, err := BulletproofGeneratorsCreate(context, &GeneratorG, 2*64*2)
	// if err != nil {
	//     return
	// }
	// defer BulletproofGeneratorsDestroy(context, generators)

	value := uint64(12345678)

	blind := Random256()
	nonce := Random256()
	assert.NoError(t, err)

	commit, err := Commit(context, blind[:], value, &GeneratorG)
	assert.NoError(t, err)

	//proof, err := RangeproofProveSingle(context, nil, nil, value, blind[:], blind[:], nil, nil, nil)
	proof, err := RangeproofSign(context, 0, commit, blind[:], nonce[:], 0, 0, uint64(value), nil, nil, &GeneratorG)
	assert.NoError(t, err)

	for i := 0; i < 1000; i++ {
		//bulletproof, _, _, _, err := BulletproofRangeproofProve(context, scratch, generators, taux, &tone, &ttwo, []uint64{value}, nil, [][32]byte{blinding}, []*Commitment
		prooferr := RangeproofVerify(context, proof, commit, nil, &GeneratorG)
		assert.True(t, prooferr)
	}

	//prooferr = BulletproofRangeproofVerifySingle(context, nil, nil, proof, commit, nil)
	//assert.NoError(t, prooferr)
}
