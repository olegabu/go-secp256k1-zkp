package secp256k1_test

import (
	"encoding/hex"
	"github.com/olegabu/go-secp256k1-zkp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSpecEcdh(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	alice := []byte{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41}
	bob := []byte{0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40}
	expected, _ := hex.DecodeString("238c14f420887f8e9bfa78bc9bdded1975f0bb6384e33b4ebbf7a8c776844aec")

	r, Alice, err := secp256k1.EcPubkeyCreate(ctx, alice)
	spOK(t, r, err)

	r, Bob, err := secp256k1.EcPubkeyCreate(ctx, bob)
	spOK(t, r, err)

	// Test case: a*B == A*b == expected
	r, bobSecret, err := secp256k1.Ecdh(ctx, Alice, bob)
	spOK(t, r, err)

	r, aliceSecret, err := secp256k1.Ecdh(ctx, Bob, alice)
	spOK(t, r, err)

	assert.Equal(t, expected, aliceSecret)
	assert.Equal(t, expected, bobSecret)
}
