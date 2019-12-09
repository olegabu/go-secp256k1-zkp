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

func TestAggsigSignSingle(t *testing.T) {
	sign, _ := ContextCreate(ContextSign)
	vrfy, _ := ContextCreate(ContextVerify)

	var err error
	var sec_nonces [2][32]byte
	sec_nonces[0], err = AggsigGenerateSecureNonce(sign, nil)
	assert.NoError(t, err)
	sec_nonces[1], err = AggsigGenerateSecureNonce(sign, nil)
	assert.NoError(t, err)

	var res int
	var pub_nonces [2]*PublicKey
	res, pub_nonces[0], err = EcPubkeyCreate(ctx, sec_nonces[0][:])
	assert.True(t, res == 1)
	assert.NoError(t, err)
	res, pub_nonces[1], err = EcPubkeyCreate(ctx, sec_nonces[1][:])
	assert.True(t, res == 1)
	assert.NoError(t, err)

	var seckeys [2][32]byte
	seckeys[0] = Random256()
	assert.NoError(t, err)
	seckeys[1] = Random256()
	assert.NoError(t, err)

	var pubkeys [2]*PublicKey
	res, pubkeys[0], err = EcPubkeyCreate(ctx, seckeys[0][:])
	assert.True(t, res == 1)
	res, pubkeys[1], err = EcPubkeyCreate(ctx, seckeys[1][:])
	assert.True(t, res == 1)

	/* Combine pubkeys */
	var pubkey_combiner [2]*PublicKey
	pubkey_combiner[0] = pub_nonces[0]
	pubkey_combiner[1] = pub_nonces[1]
	res, combiner_sum, err := EcPubkeyCombine(ctx, pubkey_combiner[:])
	assert.True(t, res == 1)
	pubkey_combiner[0] = pubkeys[0]
	pubkey_combiner[1] = pubkeys[1]
	res, combiner_sum_2, err := EcPubkeyCombine(ctx, pubkey_combiner[:])
	assert.True(t, res == 1)

	msg := Random256()

	/* Create 2 partial signatures (Sender, Receiver)*/
	sig, err := AggsigSignSingle(sign, msg[:], seckeys[0][:], sec_nonces[0][:], nil, combiner_sum, combiner_sum, combiner_sum_2, nil)
	assert.NoError(t, err)

	/* Receiver verifies sender's Sig and signs */
	err = AggsigVerifySingle(vrfy, sig, msg[:], combiner_sum, pubkeys[0], combiner_sum_2, nil, true)
	assert.NoError(t, err)
	sig2, err := AggsigSignSingle(sign, msg[:], seckeys[1][:], sec_nonces[1][:], nil, combiner_sum, combiner_sum, combiner_sum_2, nil)
	assert.NoError(t, err)
	/* sender verifies receiver's Sig then creates final combined sig */
	err = AggsigVerifySingle(vrfy, sig2, msg[:], combiner_sum, pubkeys[1], combiner_sum_2, nil, true)
	assert.NoError(t, err)

	var sigs [2][]byte
	sigs[0] = sig
	sigs[1] = sig2
	/* Add 2 sigs and nonces */
	combined_sig, err := AggsigAddSignaturesSingle(sign, sigs[:], combiner_sum)
	assert.NoError(t, err)

	/* Ensure added sigs verify properly (with and without providing nonce_sum */
	err = AggsigVerifySingle(vrfy, combined_sig, msg[:], combiner_sum, combiner_sum_2, combiner_sum_2, nil, false)
	assert.NoError(t, err)
	err = AggsigVerifySingle(vrfy, combined_sig, msg[:], nil, combiner_sum_2, combiner_sum_2, nil, false)
	assert.NoError(t, err)

}
