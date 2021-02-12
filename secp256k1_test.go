package secp256k1

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testingRand32() [32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return key
}

func TestRand256(t *testing.T) {

	rnd := [2][32]byte{Random256(), Random256()}
	fmt.Printf("Random256(): %x\nRandom256(): %x\n", rnd[0], rnd[1])
	assert.NotEmpty(t, rnd[0][:])
	assert.NotEmpty(t, rnd[1][:])
	assert.NotEqual(t, rnd[0], rnd[1])
}

func Test_ContextCreate1(t *testing.T) {

	params := uint(ContextSign | ContextVerify)
	ctx, err := ContextCreate(params)

	assert.NoError(t, err)
	assert.NotNil(t, ctx)
	assert.IsType(t, Context{}, *ctx)

	clone, err := ContextClone(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, ctx)
	assert.IsType(t, Context{}, *ctx)

	ContextDestroy(clone)

	res := ContextRandomize(ctx, testingRand32())
	assert.Equal(t, 1, res)

	ContextDestroy(ctx)
}
