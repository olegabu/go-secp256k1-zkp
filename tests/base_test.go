package secp256k1_test

import (
	"fmt"
	"github.com/olegabu/go-secp256k1-zkp"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	EcdsaTestVectors           = "sign_vectors.yaml"
	PubkeyCreateTestVectors    = "pubkey_vectors.yaml"
	PubkeyTweakAddTestVectors  = "pubkey_tweak_add_vectors.yaml"
	PubkeyTweakMulTestVectors  = "pubkey_tweak_mul_vectors.yaml"
	PrivkeyTweakAddTestVectors = "privkey_tweak_add_vectors.yaml"
	PrivkeyTweakMulTestVectors = "privkey_tweak_mul_vectors.yaml"
	TestCaseFmt                = "Test case %d"
)

func desc(i int) string {
	return fmt.Sprintf(TestCaseFmt, i)
}

func spOK(t *testing.T, result interface{}, err error) {
	assert.NoError(t, err)
	switch result := result.(type) {
	case int:
		assert.Equal(t, 1, result)
	case bool:
		assert.True(t, result)
	}
}

func readFile(filename string) []byte {
	source, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	return source
}

func removeSigHash(sig string) string {
	return strings.TrimSuffix(sig, "01")
}

func assertCanReadAndWritePublicKey(t *testing.T, ctx *secp256k1.Context, pkBytes []byte, flag uint) {
	r, pubkey, err := secp256k1.EcPubkeyParse(ctx, pkBytes)
	spOK(t, r, err)

	r, serialized, err := secp256k1.EcPubkeySerialize(ctx, pubkey, flag)
	spOK(t, r, err)
	assert.Equal(t, pkBytes, serialized)
}
