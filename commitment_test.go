package secp256k1

import (
	"crypto/rand"
	"fmt"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestCommitmentAPI(t *testing.T) {

	ctxNone, _ := ContextCreate(ContextNone)
	defer ContextDestroy(ctxNone)
	ctxSign, _ := ContextCreate(ContextSign)
	defer ContextDestroy(ctxSign)
	ctxVrfy, _ := ContextCreate(ContextVerify)
	defer ContextDestroy(ctxVrfy)
	ctxBoth, _ := ContextCreate(ContextVerify | ContextSign)
	defer ContextDestroy(ctxBoth)

	var valuebytes [8]byte
	valueLen, err := rand.Read(valuebytes[:])
	value := *(*uint64)(unsafe.Pointer(&valuebytes[0]))
	fmt.Printf("value=%v, valueLen=%v\n", value, valueLen)

	var blind [32]byte
	blindLen, err := rand.Read(blind[:])
	fmt.Printf("blind=%v, blindLen=%v\n", blind, blindLen)

	comNone, err := Commit(ctxNone, blind[:], value, &GeneratorH, &GeneratorG)
	assert.NoError(t, err)
	assert.NotNil(t, comNone)
	assert.IsType(t, Commitment{}, *comNone)
	fmt.Printf("comNone=%v\n", comNone)

	comSer, err := CommitmentSerialize(ctxNone, comNone)
	assert.NoError(t, err)
	assert.NotNil(t, comSer)
	fmt.Printf("comSer=%v\n", comSer)

	comHex := comNone.String()
	comUnhex, err := CommitmentFromString(comHex)
	assert.NoError(t, err)
	assert.Equal(t, comNone, comUnhex)

	comParse, err := CommitmentParse(ctxNone, comSer[:])
	assert.NoError(t, err)
	assert.NotNil(t, comParse)
	fmt.Printf("comParse=%v\n", *comParse)

	comSign, err := Commit(ctxSign, blind[:], value, &GeneratorH, &GeneratorG)
	assert.NoError(t, err)
	assert.NotNil(t, comSign)
	assert.IsType(t, Commitment{}, *comSign)
	fmt.Printf("comSign=%v\n", *comSign)

	comVrfy, err := Commit(ctxVrfy, blind[:], value, &GeneratorH, &GeneratorG)
	assert.NoError(t, err)
	assert.NotNil(t, comVrfy)
	assert.IsType(t, Commitment{}, *comVrfy)
	fmt.Printf("comVrfy=%v\n", *comVrfy)

	comBoth, err := Commit(ctxBoth, blind[:], value, &GeneratorH, &GeneratorG)
	assert.NoError(t, err)
	assert.IsType(t, Commitment{}, *comBoth)
	fmt.Printf("comBoth=%v\n", *comBoth)

	blindarr := [1][]byte{blind[:]}
	blindout, err := BlindSum(ctxNone, blindarr[:], nil)
	assert.NoError(t, err)
	fmt.Printf("blindout=%v\n", blindout)
}
