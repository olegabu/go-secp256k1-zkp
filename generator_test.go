package secp256k1

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratorAPI(t *testing.T) {

	ctxNone, err := ContextCreate(ContextNone)
	assert.NoError(t, err)
	assert.NotNil(t, ctxNone)
	assert.IsType(t, Context{}, *ctxNone)

	ctxSign, err := ContextCreate(ContextSign)
	assert.NoError(t, err)
	assert.NotNil(t, ctxSign)
	assert.IsType(t, Context{}, *ctxSign)

	ctxVrfy, err := ContextCreate(ContextVerify)
	assert.NoError(t, err)
	assert.NotNil(t, ctxVrfy)
	assert.IsType(t, Context{}, *ctxVrfy)

	ctxBoth, err := ContextCreate(ContextBoth)
	assert.NoError(t, err)
	assert.NotNil(t, ctxBoth)
	assert.IsType(t, Context{}, *ctxBoth)

	var key [32]byte
	keyLen, err := rand.Read(key[:])
	assert.NoError(t, err)
	assert.Equal(t, keyLen, 32)
	fmt.Printf("key = %v\n", key)

	genNone, err := GeneratorGenerate(ctxNone, key[:])
	assert.NoError(t, err)
	assert.NotNil(t, genNone)
	assert.IsType(t, Generator{}, *genNone)
	fmt.Printf("genNone = %v\n", genNone)

	genSign, err := GeneratorGenerate(ctxSign, key[:])
	assert.NoError(t, err)
	assert.NotNil(t, genSign)
	assert.IsType(t, Generator{}, *genSign)
	fmt.Printf("genSign = %s\n", genSign)

	genVrfy, err := GeneratorGenerate(ctxVrfy, key[:])
	assert.NoError(t, err)
	assert.NotNil(t, genVrfy)
	assert.IsType(t, Generator{}, *genVrfy)
	fmt.Printf("genVrfy = %s\n", genVrfy)

	genBoth, err := GeneratorGenerate(ctxBoth, key[:])
	assert.NoError(t, err)
	assert.NotNil(t, genBoth)
	assert.IsType(t, Generator{}, *genBoth)
	fmt.Printf("genBoth = %s\n", genBoth)

	var blind [32]byte
	blindLen, err := rand.Read(blind[:])
	assert.NoError(t, err)
	assert.Equal(t, blindLen, 32)
	fmt.Printf("blind = %v\n", blind)

	genSignBlinded, err := GeneratorGenerateBlinded(ctxSign, key[:], blind[:])
	assert.NoError(t, err)
	assert.NotNil(t, genSignBlinded)
	assert.IsType(t, Generator{}, *genSignBlinded)
	fmt.Printf("genSignBlinded = %s\n", genSignBlinded)

	genSignBlindedSerialized := GeneratorSerialize(ctxSign, genSignBlinded)
	assert.NoError(t, err)
	assert.NotEmpty(t, genSignBlindedSerialized)
	fmt.Printf("genSignBlindedSerialized = %v\n", genSignBlindedSerialized)

	genSignBlindedParsed, err := GeneratorParse(ctxSign, genSignBlindedSerialized[:])
	assert.NoError(t, err)
	assert.NotNil(t, genSignBlindedParsed)
	assert.IsType(t, Generator{}, *genSignBlindedParsed)
	fmt.Printf("genSignBlindedParsed = %s\n", genSignBlindedParsed)

	gen2hex := genSignBlinded.String()
	hex2gen := gen2hex.
		ContextDestroy(ctxBoth)
	ContextDestroy(ctxVrfy)
	ContextDestroy(ctxSign)
	ContextDestroy(ctxNone)
}
