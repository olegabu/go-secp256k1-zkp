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

func TestAggsigSignSingle(t *testing.T) {
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
	ok, err := AggsigVerifySingle(ctx, sig, message[:], nil, pubkey, nil, nil, noneg)
	assert.True(t, ok)
	assert.NoError(t, err)
}
