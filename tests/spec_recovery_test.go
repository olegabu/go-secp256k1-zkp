package secp256k1_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"labdlt.ru/mw/go-secp256k1-zkp"
)

func TestSpecRecoverableSignature(t *testing.T) {
	context, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	msg32 := testingRand(32)
	priv := testingRand(32)

	r, sig, err := secp256k1.EcdsaSignRecoverable(context, msg32, priv)
	spOK(t, r, err)

	// Converted signature can be verified against pubkey

	r, plain, err := secp256k1.EcdsaRecoverableSignatureConvert(context, sig)
	spOK(t, r, err)

	r, pub, err := secp256k1.EcPubkeyCreate(context, priv)
	spOK(t, r, err)

	r, err = secp256k1.EcdsaVerify(context, plain, msg32, pub)
	spOK(t, r, err)

	// Can serialize recoverable signature

	r, sig64, recid, err := secp256k1.EcdsaRecoverableSignatureSerializeCompact(context, sig)
	spOK(t, r, err)

	assert.NotEmpty(t, sig64)

	r, sigParsed, err := secp256k1.EcdsaRecoverableSignatureParseCompact(context, sig64, recid)
	spOK(t, r, err)

	assert.Equal(t, sig, sigParsed)

	// Recovers correct public key

	r, pubkeyRec, err := secp256k1.EcdsaRecover(context, sig, msg32)
	spOK(t, r, err)

	assert.Equal(t, pub, pubkeyRec)
}
