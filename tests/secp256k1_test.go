package secp256k1_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"labdlt.ru/mw/go-secp256k1-zkp"
)

func testingRand32() [32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return key
}
func testingRand(n int) []byte {
	key := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return key
}

func Test_ContextCreate1(t *testing.T) {

	params := uint(secp256k1.ContextSign | secp256k1.ContextVerify)
	ctx, err := secp256k1.ContextCreate(params)

	assert.NoError(t, err)
	assert.NotNil(t, ctx)
	assert.IsType(t, secp256k1.Context{}, *ctx)

	clone, err := secp256k1.ContextClone(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, ctx)
	assert.IsType(t, secp256k1.Context{}, *ctx)

	secp256k1.ContextDestroy(clone)

	res := secp256k1.ContextRandomize(ctx, testingRand32())
	assert.Equal(t, 1, res)

	secp256k1.ContextDestroy(ctx)
}
