package secp256k1_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
	"labdlt.ru/mw/go-secp256k1-zkp"
)

type EcdsaTestCase struct {
	PrivateKey string `yaml:"privkey"`
	Message    string `yaml:"msg"`
	Sig        string `yaml:"sig"`
}

func (t *EcdsaTestCase) GetPrivateKey() []byte {
	private, err := hex.DecodeString(t.PrivateKey)
	if err != nil {
		panic("Invalid private key")
	}
	return private
}
func (t *EcdsaTestCase) GetPublicKey(ctx *secp256k1.Context) *secp256k1.PublicKey {
	private := t.GetPrivateKey()
	_, pk, err := secp256k1.EcPubkeyCreate(ctx, private)
	if err != nil {
		panic(err)
	}
	return pk
}

func (t *EcdsaTestCase) GetMessage() []byte {
	msg, err := hex.DecodeString(t.Message)
	if err != nil {
		panic("Invalid msg32")
	}
	return msg
}
func (t *EcdsaTestCase) GetSigBytes() []byte {
	sig, err := hex.DecodeString(removeSigHash(t.Sig))
	if err != nil {
		panic("Invalid msg32")
	}
	return sig
}
func (t *EcdsaTestCase) GetSig(ctx *secp256k1.Context) *secp256k1.EcdsaSignature {
	sigb := t.GetSigBytes()
	_, sig, err := secp256k1.EcdsaSignatureParseDer(ctx, sigb)
	if err != nil {
		panic(err)
	}
	return sig
}

type EcdsaFixtures []EcdsaTestCase

func GetEcdsaFixtures() []EcdsaTestCase {
	source := readFile(EcdsaTestVectors)
	testCase := EcdsaFixtures{}
	err := yaml.Unmarshal(source, &testCase)
	if err != nil {
		panic(err)
	}
	return testCase
}

/*func Test_Ecdsa_InvalidSig(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	sig := newEcdsaSignature()
	pk := newPublicKey()
	r, err := secp256k1.EcdsaVerify(ctx, sig, []byte{}, pk)
	assert.Error(t, err)
	assert.Equal(t, 0, r)
}*/

func Test_Ecdsa_Verify(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetEcdsaFixtures()

	for i := 0; i < len(fixtures); i++ {
		testCase := fixtures[i]
		msg32 := testCase.GetMessage()
		pubkey := testCase.GetPublicKey(ctx)
		sig := testCase.GetSig(ctx)

		result, err := secp256k1.EcdsaVerify(ctx, sig, msg32, pubkey)
		spOK(t, result, err)
	}
}

func Test_Ecdsa_Sign(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetEcdsaFixtures()
	for i := 0; i < len(fixtures); i++ {
		testCase := fixtures[i]
		msg32 := testCase.GetMessage()
		priv := testCase.GetPrivateKey()
		sigb := testCase.GetSigBytes()

		r, sig, err := secp256k1.EcdsaSign(ctx, msg32, priv)

		spOK(t, r, err)

		r, serialized, err := secp256k1.EcdsaSignatureSerializeDer(ctx, sig)
		assert.Equal(t, sigb, serialized)
	}
}
