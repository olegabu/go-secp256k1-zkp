package secp256k1_test

import (
	"github.com/olegabu/go-secp256k1-zkp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ContextCreate_Clone_Destroy(t *testing.T) {
	vFlags := make([]uint, 3)
	vFlags[0] = uint(secp256k1.ContextSign)
	vFlags[1] = uint(secp256k1.ContextVerify)
	vFlags[2] = uint(secp256k1.ContextSign | secp256k1.ContextVerify)

	for i := 0; i < len(vFlags); i++ {

		ctx, err := secp256k1.ContextCreate(vFlags[i])
		assert.NoError(t, err)
		assert.NotNil(t, ctx)
		assert.IsType(t, secp256k1.Context{}, *ctx)

		clone, err := secp256k1.ContextClone(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, ctx)
		assert.IsType(t, secp256k1.Context{}, *ctx)

		secp256k1.ContextDestroy(clone)
		secp256k1.ContextDestroy(ctx)
	}
}
