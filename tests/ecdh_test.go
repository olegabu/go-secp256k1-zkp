package secp256k1_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"labdlt.ru/mw/go-secp256k1-zkp"
)

func TestEcdhCatchesOverflow(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	alice, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142")
	bob := []byte{0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40}

	r, Bob, err := secp256k1.EcPubkeyCreate(ctx, bob)
	spOK(t, r, err)

	r, _, err = secp256k1.Ecdh(ctx, Bob, alice)
	assert.Equal(t, 0, r)
	assert.Error(t, err)
	assert.Equal(t, secp256k1.ErrorEcdh, err.Error())
}

func TestEcdhInvalidKey(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	alice, _ := hex.DecodeString("")
	bob := []byte{0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40}

	r, Bob, err := secp256k1.EcPubkeyCreate(ctx, bob)
	spOK(t, r, err)

	r, _, err = secp256k1.Ecdh(ctx, Bob, alice)
	assert.Equal(t, 0, r)
	assert.Error(t, err)
	assert.Equal(t, secp256k1.ErrorPrivateKeySize, err.Error())
}
