package secp256k1_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"labdlt.ru/mw/go-secp256k1-zkp"
)

func TestParseRecoverableSignatureErrors(t *testing.T) {
	badSig, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142")

	testCase := []struct {
		Sig64 []byte
		RecId int
		Error string
	}{
		{
			Sig64: []byte(`a`),
			RecId: 0,
			Error: secp256k1.ErrorCompactSigSize,
		},
		{
			Sig64: badSig,
			RecId: 0,
			Error: secp256k1.ErrorRecoverableSigParse,
		},
		{
			Sig64: badSig,
			RecId: 1,
			Error: secp256k1.ErrorRecoverableSigParse,
		},
		{
			Sig64: badSig,
			RecId: 2,
			Error: secp256k1.ErrorRecoverableSigParse,
		},
		{
			Sig64: badSig,
			RecId: 3,
			Error: secp256k1.ErrorRecoverableSigParse,
		},
	}

	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}
	for i, l := 0, len(testCase); i < l; i++ {
		description := fmt.Sprintf("Test case %d", i)
		t.Run(description, func(t *testing.T) {
			test := testCase[i]
			r, _, err := secp256k1.EcdsaRecoverableSignatureParseCompact(ctx, test.Sig64, test.RecId)
			assert.Equal(t, 0, r)
			assert.Error(t, err)
			assert.Equal(t, test.Error, err.Error())
		})
	}
}

func TestEcdsaSignRecoverableErrors(t *testing.T) {
	badKey, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142")

	testCase := []struct {
		Msg32 []byte
		Priv  []byte
		Error string
	}{
		{
			Priv:  testingRand(32),
			Msg32: []byte(`a`),
			Error: secp256k1.ErrorMsg32Size,
		},
		{
			Msg32: testingRand(32),
			Priv:  []byte(`a`),
			Error: secp256k1.ErrorPrivateKeySize,
		},
		{
			Priv:  badKey,
			Msg32: testingRand(32),
			Error: secp256k1.ErrorProducingRecoverableSignature,
		},
	}

	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}
	for i, l := 0, len(testCase); i < l; i++ {
		description := fmt.Sprintf("Test case %d", i)
		t.Run(description, func(t *testing.T) {
			test := testCase[i]
			r, _, err := secp256k1.EcdsaSignRecoverable(ctx, test.Msg32, test.Priv)
			assert.Equal(t, 0, r)
			assert.Error(t, err)
			assert.Equal(t, test.Error, err.Error())
		})
	}
}

/*
func TestEcdsaRecoverCanError(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	priv := testingRand(32)
	msg32 := testingRand(32)
	msg32_2 := []byte(`a`)

	_, sig, err := secp256k1.EcdsaSignRecoverable(ctx, msg32, priv)
	assert.NoError(t, err)

	r, _, err := secp256k1.EcdsaRecover(ctx, sig, msg32)
	assert.Equal(t, 1, r)
	assert.NoError(t, err)

	r, _, err = secp256k1.EcdsaRecover(ctx, sig, msg32_2)
	assert.Equal(t, 0, r)
	assert.Error(t, err)
	assert.Equal(t, secp256k1.ErrorMsg32Size, err.Error())

	empty := newEcdsaRecoverableSignature()
	r, _, err = EcdsaRecover(ctx, empty, msg32)
	assert.Equal(t, 0, r)
	assert.Error(t, err)
	assert.Equal(t, ErrorRecoveryFailed, err.Error())
}
*/ /*
func TestSerializeRecoverableSignatureWorksIfNull(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	sig := newEcdsaRecoverableSignature()

	r, sig64, recid, err := EcdsaRecoverableSignatureSerializeCompact(ctx, sig)
	assert.NoError(t, err)
	assert.Equal(t, 1, r)
	assert.Equal(t, 0, recid)
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, sig64)

}
*/
