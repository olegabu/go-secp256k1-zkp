package secp256k1

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRangeProofSign(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/rangeproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
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

		proof, err := RangeProofSign(ctx, uint64(minValue), commit, blind, nonce, 0, 0, uint64(value), message, extraCommit, gen)
		assert.NoError(t, err)
		assert.NotNil(t, proof)
		assert.Equal(t, v["expected"].(string), hex.EncodeToString(proof))
	}
}

func TestRangeProofInfo(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/rangeproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
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

		exp, mantissa, minValue, maxValue, err := RangeProofInfo(ctx, proof)
		assert.NoError(t, err)
		assert.Equal(t, expectedExp, exp)
		assert.Equal(t, expectedMantissa, mantissa)
		assert.Equal(t, uint64(expectedMinValue), minValue)
		assert.Equal(t, uint64(expectedMaxValue), maxValue)
	}
}

func TestRangeProofVerify(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/rangeproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
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
			RangeProofVerify(ctx, proof, commit, extraCommit, generator),
		)
	}
}

func TestRangeProofRewind(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/rangeproof.json")
	assert.NoError(t, err)

	var tests map[string]interface{}
	json.Unmarshal(file, &tests)
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
			RangeProofRewind(ctx, commit, proof, nonce, extraCommit, generator)
		assert.NoError(t, err)
		expected := v["expected"].(map[string]interface{})
		assert.Equal(t, expected["value"], strconv.Itoa(int(value)))
		assert.Equal(t, expected["minValue"], strconv.Itoa(int(minValue)))
		assert.Equal(t, expected["maxValue"], strconv.Itoa(int(maxValue)))
		assert.Equal(t, expected["blindFactor"], hex.EncodeToString(blindingFactor[:]))
		assert.Equal(t, expected["message"].(string), hex.EncodeToString(message[:]))
	}
}
