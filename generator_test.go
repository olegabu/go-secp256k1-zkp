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
	defer ContextDestroy(ctxNone)

	ctxSign, err := ContextCreate(ContextSign)
	assert.NoError(t, err)
	assert.NotNil(t, ctxSign)
	assert.IsType(t, Context{}, *ctxSign)
	defer ContextDestroy(ctxSign)

	ctxVrfy, err := ContextCreate(ContextVerify)
	assert.NoError(t, err)
	assert.NotNil(t, ctxVrfy)
	assert.IsType(t, Context{}, *ctxVrfy)
	defer ContextDestroy(ctxVrfy)

	ctxBoth, err := ContextCreate(ContextBoth)
	assert.NoError(t, err)
	assert.NotNil(t, ctxBoth)
	assert.IsType(t, Context{}, *ctxBoth)
	defer ContextDestroy(ctxBoth)

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
	fmt.Printf("genSignBlinded = %s\n", genSignBlinded)

	genSignBlindedStr := genSignBlinded.String()
	genSignBlindedBytes := genSignBlinded.Bytes()
	genSignBlindedArray := GeneratorSerialize(ctxSign, genSignBlinded)
	assert.Equal(t, genSignBlindedArray[:], genSignBlindedBytes[:])
	assert.NotEmpty(t, genSignBlindedArray)
	assert.NotEmpty(t, genSignBlindedStr)
	fmt.Printf("genSignBlindedSerialized bytes: %s, string: %s\n", genSignBlindedBytes, genSignBlindedStr)

	genSignBlindedFromArray, err := GeneratorParse(ctxSign, genSignBlindedArray[:])
	genSignBlindedFromStr, err := GeneratorFromString(genSignBlindedStr)
	genSignBlindedFromBytes, err := GeneratorFromBytes(genSignBlindedBytes[:])
	assert.NotEmpty(t, genSignBlindedFromArray)
	assert.NotEmpty(t, genSignBlindedFromStr)
	fmt.Printf("genSignBlindedParsed = %s, from str = %s\n", genSignBlindedFromBytes, genSignBlindedFromStr)

}
