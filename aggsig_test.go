package secp256k1

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// Testing aggsig exchange algorithm for Grin
func TestAggsigGrin(t *testing.T) {

	ctx, _ := ContextCreate(ContextBoth)
	defer ContextDestroy(ctx)

	for i := 0; i < 20; i++ {

		var res int
		var err error

		var secNonces [2][32]byte
		var secBlinds [2][32]byte
		var pubNonces [2]*PublicKey
		var pubBlinds [2]*PublicKey

		// Create a pair of secret/public nonces
		secNonces[0], err = AggsigGenerateSecureNonce(ctx, nil)
		assert.NoError(t, err)
		res, pubNonces[0], err = EcPubkeyCreate(ctx, secNonces[0][:])
		assert.True(t, res == 1)
		assert.NoError(t, err)

		secNonces[1], err = AggsigGenerateSecureNonce(ctx, nil)
		assert.NoError(t, err)
		res, pubNonces[1], err = EcPubkeyCreate(ctx, secNonces[1][:])
		assert.True(t, res == 1)
		assert.NoError(t, err)

		// Randomize keys
		secBlinds[0] = Random256()
		assert.NoError(t, err)
		secBlinds[1] = Random256()
		assert.NoError(t, err)

		res, pubBlinds[0], err = EcPubkeyCreate(ctx, secBlinds[0][:])
		assert.True(t, res == 1)
		res, pubBlinds[1], err = EcPubkeyCreate(ctx, secBlinds[1][:])
		assert.True(t, res == 1)

		var combiner [2]*PublicKey

		// Combine pubnonces
		combiner[0] = pubNonces[0]
		combiner[1] = pubNonces[1]
		res, sumPubNonces, err := EcPubkeyCombine(ctx, combiner[:])
		assert.True(t, res == 1)

		// Combine pubBlinds
		combiner[0] = pubBlinds[0]
		combiner[1] = pubBlinds[1]
		res, sumPubBlinds, err := EcPubkeyCombine(ctx, combiner[:])
		assert.True(t, res == 1)

		msg32 := Random256()
		msg := msg32[:]

		// Receiver signs it's PartialSig
		s1, err := AggsigSignPartial(ctx, secBlinds[1][:], secNonces[1][:], sumPubNonces, sumPubBlinds, msg[:])
		assert.NoError(t, err)

		// Sender verifies Receiver's PartialSig
		err = AggsigVerifyPartial(ctx, &s1, sumPubNonces, pubBlinds[1], sumPubBlinds, msg[:])
		assert.NoError(t, err)

		// Sender calculates it's PartialSig
		s0, err := AggsigSignPartial(ctx, secBlinds[0][:], secNonces[0][:], sumPubNonces, sumPubBlinds, msg[:])
		assert.NoError(t, err)

		err = AggsigVerifyPartial(ctx, &s0, sumPubNonces, pubBlinds[0], sumPubBlinds, msg[:])
		assert.NoError(t, err)

		Sig, err := AggsigAddSignaturesSingle(ctx, []*AggsigSignaturePartial{&s0, &s1}, sumPubNonces)
		assert.NoError(t, err)

		// Ensure added sigs verify properly (with and without providing nonce_sum), ...
		assert.NoError(t, AggsigVerifySingle(ctx, &Sig, msg, sumPubNonces, sumPubBlinds, sumPubBlinds, nil, false))
		assert.NoError(t, AggsigVerifySingle(ctx, &Sig, msg, nil, sumPubBlinds, sumPubBlinds, nil, false))

		// ... and anything else doesn't
		assert.Error(t, AggsigVerifySingle(ctx, &Sig, msg, sumPubNonces, sumPubBlinds, nil, nil, false))
		assert.Error(t, AggsigVerifySingle(ctx, &Sig, msg, nil, pubNonces[1], nil, nil, false))
		assert.Error(t, AggsigVerifySingle(ctx, &Sig, msg, nil, pubNonces[1], sumPubBlinds, nil, false))
		assert.Error(t, AggsigVerifySingle(ctx, &Sig, msg, pubNonces[0], sumPubBlinds, nil, nil, false))
		assert.Error(t, AggsigVerifySingle(ctx, &Sig, msg, pubNonces[0], sumPubBlinds, sumPubBlinds, nil, false))
		msg[0], msg[1], msg[2] = 1, 2, 3
		assert.Error(t, AggsigVerifySingle(ctx, &Sig, msg, nil, sumPubBlinds, nil, nil, false))
		assert.Error(t, AggsigVerifySingle(ctx, &Sig, msg, nil, sumPubBlinds, sumPubBlinds, nil, false))

	}
}
