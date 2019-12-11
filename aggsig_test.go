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
	seed := Random256()
	message := Random256()
	seckey, seckey2 := Random256(), Random256()
	_, pubkey, _ := EcPubkeyCreate(ctx, seckey[:])
	_, pubkey2, _ := EcPubkeyCreate(ctx, seckey2[:])
	_, pubkeys, _ := EcPubkeyCombine(ctx, []*PublicKey{pubkey, pubkey2})

	sig, err := AggsigSignSingle(ctx, message[:], seckey[:], nil, nil, nil, nil, nil, seed[:])
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	sig2, err := AggsigSignSingle(ctx, message[:], seckey2[:], nil, nil, nil, nil, nil, seed[:])
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	sigs, err := AggsigAddSignaturesSingle(ctx, [][]byte{sig, sig2}, pubkeys)
	assert.NoError(t, err)
	assert.NotNil(t, sigs)

	var noneg bool = true
	err = AggsigVerifySingle(ctx, sig, message[:], nil, pubkey, nil, nil, noneg)
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

	var sigs [3][]byte

	for i := 0; i < 20; i++ {

		var res int
		var err error

		var secNonces [2][32]byte
		var secBlinds [2][32]byte
		var pubNonces [2]*PublicKey
		var pubBlinds [2]*PublicKey

		// Create a couple of nonces
		secNonces[0], err = AggsigGenerateSecureNonce(sign, nil)
		assert.NoError(t, err)
		secNonces[1], err = AggsigGenerateSecureNonce(sign, nil)
		assert.NoError(t, err)

		res, pubNonces[0], err = EcPubkeyCreate(ctx, secNonces[0][:])
		assert.True(t, res == 1)
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
		//sigs[1], err = AggsigSignSingle(sign, msg[:], secBlinds[1][:], secNonces[1][:], nil, sumPubNonces, sumPubBlinds, sumPubNonces, nil)
		sigs[1], err = AggsigSignSingle(sign, msg[:], secBlinds[1][:], secNonces[1][:], nil, sumPubNonces, sumPubNonces, sumPubBlinds, nil)
		assert.NoError(t, err)

		// Sender verifies Receiver's Sig then creates final combined Sig
		err = AggsigVerifySingle(vrfy, sigs[1], msg[:], sumPubNonces, pubBlinds[1], sumPubBlinds, nil, true)
		assert.NoError(t, err)

		// Sender calculates it's signature
		//sigs[0], err = AggsigSignSingle(sign, msg[:], secBlinds[0][:], secNonces[0][:], nil, sumPubNonces, sumPubBlinds, sumPubNonces, nil)
		sigs[0], err = AggsigSignSingle(sign, msg[:], secBlinds[0][:], secNonces[0][:], nil, sumPubNonces, sumPubNonces, sumPubBlinds, nil)
		assert.NoError(t, err)

		err = AggsigVerifySingle(vrfy, sigs[0], msg[:], sumPubNonces, pubBlinds[0], sumPubBlinds, nil, true)
		assert.NoError(t, err)

		// Add 2 sigs and nonces
		sigs[2], err = AggsigAddSignaturesSingle(sign, sigs[:2], sumPubNonces)
		assert.NoError(t, err)

		// Ensure added sigs verify properly (with and without providing nonce_sum), ...
		assert.NoError(t, AggsigVerifySingle(vrfy, sigs[2], msg, sumPubNonces, sumPubBlinds, sumPubBlinds, nil, false))
		assert.NoError(t, AggsigVerifySingle(vrfy, sigs[2], msg, nil, sumPubBlinds, sumPubBlinds, nil, false))

		// ... and anything else doesn't
		assert.Error(t, AggsigVerifySingle(vrfy, sigs[2], msg, sumPubNonces, sumPubBlinds, nil, nil, false))
		assert.Error(t, AggsigVerifySingle(vrfy, sigs[2], msg, nil, pubNonces[1], nil, nil, false))
		assert.Error(t, AggsigVerifySingle(vrfy, sigs[2], msg, nil, pubNonces[1], sumPubBlinds, nil, false))
		assert.Error(t, AggsigVerifySingle(vrfy, sigs[2], msg, pubNonces[0], sumPubBlinds, nil, nil, false))
		assert.Error(t, AggsigVerifySingle(vrfy, sigs[2], msg, pubNonces[0], sumPubBlinds, sumPubBlinds, nil, false))
		msg[0] = 1
		msg[1] = 2
		msg[2] = 3
		assert.Error(t, AggsigVerifySingle(vrfy, sigs[2], msg, nil, sumPubBlinds, nil, nil, false))
		assert.Error(t, AggsigVerifySingle(vrfy, sigs[2], msg, nil, sumPubBlinds, sumPubBlinds, nil, false))
		
	}
	
	// **** End aggsig for Grin exchange test **** //
	// /////////////////////////////////////////// //
}
