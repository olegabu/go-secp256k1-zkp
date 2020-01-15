package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var ctx *Context

func init() {
	var err error
	ctx, err = ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}
}

func TestAggsigContext(t *testing.T) {

	message := Random256()
	seckey, seckey2 := Random256(), Random256()
	_, pubkey, _ := EcPubkeyCreate(ctx, seckey[:])
	_, pubkey2, _ := EcPubkeyCreate(ctx, seckey2[:])
	_, pubkeys, _ := EcPubkeyCombine(ctx, []*PublicKey{pubkey, pubkey2})

	sig, err := AggsigSignPartial(ctx, message[:], seckey[:], nil, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	sig2, err := AggsigSignPartial(ctx, message[:], seckey2[:], nil, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	sigs, err := AggsigAddSignaturesSingle(ctx, []*AggsigSignaturePartial{&sig, &sig2}, pubkeys)
	assert.NoError(t, err)
	assert.NotNil(t, sigs)

	err = AggsigVerifySingle(ctx, &sigs, message[:], nil, pubkey, nil, nil, false)
	assert.NoError(t, err)
}

func TestAggsigGrin(t *testing.T) {

	// Context objs
	sign, _ := ContextCreate(ContextSign)
	vrfy, _ := ContextCreate(ContextVerify)

	// Cleanup at scope exit
	defer ContextDestroy(sign)
	defer ContextDestroy(vrfy)

	// //////////////////////////////////////////////////// //
	// **** Testing aggsig exchange algorithm for Grin **** //

	var sigs [3]*AggsigSignaturePartial
	var Sig AggsigSignature

	for i := 0; i < 20; i++ {

		var res int
		var err error

		var secNonces [2][32]byte
		var secBlinds [2][32]byte
		var pubNonces [2]*PublicKey
		var pubBlinds [2]*PublicKey

		// Create a pair of secret/public nonces
		secNonces[0], err = AggsigGenerateSecureNonce(sign, nil)
		assert.NoError(t, err)
		res, pubNonces[0], err = EcPubkeyCreate(ctx, secNonces[0][:])
		assert.True(t, res == 1)
		assert.NoError(t, err)

		secNonces[1], err = AggsigGenerateSecureNonce(sign, nil)
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

		// Create 2 partial signatures (Sender, Receiver)
		// sigs[0], err = AggsigSignSingle(sign, msg[:], secBlinds[0][:], secNonces[0][:], nil, sumPubNonces, sumPubNonces, sumPubBlinds, nil)
		// assert.NoError(t, err)

		// ... and Receiver signs it's Sig
		// sigs[1], err = AggsigSignSingle(sign, msg[:], secBlinds[1][:], secNonces[1][:], nil, sumPubNonces, sumPubBlinds, sumPubNonces, nil)
		s1, err := AggsigSignPartial(sign, secBlinds[1][:], secNonces[1][:], sumPubNonces, sumPubBlinds, msg[:])
		assert.NoError(t, err)

		// Sender verifies Receiver's Sig then creates final combined Sig
		err = AggsigVerifyPartial(vrfy, &s1, sumPubNonces, pubBlinds[1], sumPubBlinds, msg[:])
		assert.NoError(t, err)

		// Sender calculates it's signature
		// sigs[0], err = AggsigSignSingle(sign, msg[:], secBlinds[0][:], secNonces[0][:], nil, sumPubNonces, sumPubBlinds, sumPubNonces, nil)
		s0, err := AggsigSignPartial(sign, secBlinds[0][:], secNonces[0][:], sumPubNonces, sumPubBlinds, msg[:])
		assert.NoError(t, err)
		sigs[0] = &s0
		sigs[1] = &s1

		err = AggsigVerifyPartial(vrfy, &s0, sumPubNonces, pubBlinds[0], sumPubBlinds, msg[:])
		assert.NoError(t, err)

		// Add 2 sigs and nonces
		var sigs2 [2]*AggsigSignaturePartial
		for i, s := range sigs[:2] {
			sigs2[i] = s
		}
		Sig, err = AggsigAddSignaturesSingle(sign, sigs2[:], sumPubNonces)
		assert.NoError(t, err)

		// Ensure added sigs verify properly (with and without providing nonce_sum), ...
		assert.NoError(t, AggsigVerifySingle(vrfy, &Sig, msg, sumPubNonces, sumPubBlinds, sumPubBlinds, nil, false))
		assert.NoError(t, AggsigVerifySingle(vrfy, &Sig, msg, nil, sumPubBlinds, sumPubBlinds, nil, false))
		assert.NoError(t, AggsigVerifySingle(vrfy, &Sig, msg, nil, sumPubBlinds, nil, nil, false))

		// ... and anything else doesn't
		assert.Error(t, AggsigVerifySingle(vrfy, &Sig, msg, sumPubNonces, sumPubBlinds, nil, nil, false))
		assert.Error(t, AggsigVerifySingle(vrfy, &Sig, msg, nil, pubNonces[1], nil, nil, false))
		assert.Error(t, AggsigVerifySingle(vrfy, &Sig, msg, nil, pubNonces[1], sumPubBlinds, nil, false))
		assert.Error(t, AggsigVerifySingle(vrfy, &Sig, msg, pubNonces[0], sumPubBlinds, nil, nil, false))
		assert.Error(t, AggsigVerifySingle(vrfy, &Sig, msg, pubNonces[0], sumPubBlinds, sumPubBlinds, nil, false))
		msg[0] = 1
		msg[1] = 2
		msg[2] = 3
		assert.Error(t, AggsigVerifySingle(vrfy, &Sig, msg, nil, sumPubBlinds, nil, nil, false))
		assert.Error(t, AggsigVerifySingle(vrfy, &Sig, msg, nil, sumPubBlinds, sumPubBlinds, nil, false))

	}

	// **** End aggsig for Grin exchange test **** //
	// /////////////////////////////////////////// //
}
