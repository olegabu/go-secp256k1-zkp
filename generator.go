/*
 This package implements Zero Knowledge Proof algorithms for Golang
 Contains Go bindings for the secp256k1-zkp C-library, which is
 based on the secp256k1 - a highly optimized implementation of the
 256-bit elliptic curve used in Bitcoin blockchain.
*/
package secp256k1

/*
#include "include/secp256k1_generator.h"
#cgo CFLAGS: -I${SRCDIR}/secp256k1-zkp -I${SRCDIR}/secp256k1-zkp/src
*/
import "C"
import (
	"encoding/hex"
	"errors"
)

/******************************************************************************
 Pointer to opaque data structure that stores a base point
 ---------------------------------------------------------
 The exact representation of data inside is implementation defined and not
 guaranteed to be portable between different platforms or versions. It is
 however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 If you need to convert to a format suitable for storage, transmission, or
 comparison, use secp256k1_generator_serialize and secp256k1_generator_parse.
*******************************************************************************/
type Generator struct {
	gen *C.secp256k1_generator
}

const (
	ErrorGeneratorParse    string = "failed to parse data as a generator"
	ErrorGeneratorGenerate string = "failed to create a generator"
)

var (
	// Standard secp256k1 generator G
	GeneratorG = Generator{&C.secp256k1_generator_const_g}
	// Alternate secp256k1 generator from Elements Alpha
	GeneratorH = Generator{&C.secp256k1_generator_const_h}
)

type GeneratorSerialized = [33]byte

// type GeneratorSerializedSlice = []byte

func newGenerator() *Generator {
	return &Generator{
		gen: &C.secp256k1_generator{},
	}
}

// Parse a 33-byte generator byte sequence into a generator object.
// -> context   a secp256k1 context object.
// -> bytes     33-byte slice of data
// <- generator pointer to a generator object
// <- err       nil if success or an error object
func GeneratorParse(
	context *Context,
	bytes []byte,
) (
	generator *Generator,
	err error,
) {
	if LenCompressed != len(bytes) {
		return nil, errors.New(ErrorGeneratorParse + " (invalid length)")
	}
	generator = newGenerator()
	if 1 != C.secp256k1_generator_parse(
		context.ctx,
		generator.gen,
		cBuf(bytes)) {

		return nil, errors.New(ErrorGeneratorParse)
	}

	return
}

// Serialize a 33-byte generator into a serialized byte sequence
//  -> context   non-NULL context
//  -> generator generator object
//  <- bytes     33 bytes of data
func GeneratorSerialize(
	context *Context,
	generator *Generator,
) (
	bytes [33]byte,
) {
	C.secp256k1_generator_serialize(
		context.ctx,
		cBuf(bytes[:]),
		generator.gen)

	return
}

var ctxNone *Context

func init() {
	var err error
	ctxNone, err = ContextCreate(ContextNone)
	if err != nil {
		panic("error creating default context object for generators")
	}
}

// String method serializes generator as a hex string
func (gen *Generator) String() string {
	bytes := GeneratorSerialize(ctxNone, gen)

	return hex.EncodeToString(bytes[:])
}

// Generator returns object created from serialized data bytes
// Returns nil if failed to parse
func (genser GeneratorSerialized) Generator() (generator *Generator) {
	var err error
	if generator, err = GeneratorParse(ctxNone, genser[:]); err == nil {

		return nil
	}

	return
}

func (genser *GeneratorSerialized) Generator() (generator *Generator) {
	var err error
	if generator, err = GeneratorParse(ctxNone, genser[:]); err == nil {

		return nil
	}

	return
}

type GeneratorSerializedHex string

func (genhex GeneratorSerializedHex) Generator() (generator *Generator) {
	str := string(genhex)
	if genser, err := hex.DecodeString(str); err == nil {

		return nil
	} else {
		if generator, err = GeneratorParse(ctxNone, genser); err == nil {

			return nil
		}
	}

	return
}

// Generate a generator for the curve.
//
//      Returns: 0 in the highly unlikely case the seed is not acceptable,
//               1 otherwise.
//      Args: ctx:     a secp256k1 context object
//      Out:  gen:     a generator object
//      In:   seed32:  a 32-byte seed
//
//      If successful a valid generator will be placed in gen. The produced
//      generators are distributed uniformly over the curve, and will not have a
//      known discrete logarithm with respect to any other generator produced,
//      or to the base generator G.
//
func GeneratorGenerate(ctx *Context, seed []byte) (*Generator, error) {
	generator := newGenerator()

	if 1 != C.secp256k1_generator_generate(
		ctx.ctx,
		generator.gen,
		cBuf(seed)) {

		return nil, errors.New(ErrorGeneratorGenerate)
	}

	return generator, nil
}

// Generate a blinded generator for the curve.
//
//  Returns: 0 in the highly unlikely case the seed is not acceptable or when
//           blind is out of range. 1 otherwise.
//      Args: ctx:     a secp256k1 context object, initialized for signing
//      Out:  gen:     a generator object
//      In:   seed32:  a 32-byte seed
//            blind32: a 32-byte secret value to blind the genesizeofrator with.
//
//      The result is equivalent to first calling secp256k1_gensizeoferator_generate,
//      converting the result to a public key, calling secp256k1_ec_pubkey_tweak_add,
//      and then converting back to generator form.sizeof
//
func GeneratorGenerateBlinded(ctx *Context, seed []byte, blind []byte) (*Generator, error) {
	generator := newGenerator()
	if 1 != int(
		C.secp256k1_generator_generate_blinded(
			ctx.ctx,
			generator.gen,
			cBuf(seed),
			cBuf(blind))) {
		return nil, errors.New(ErrorGeneratorGenerate)
	}
	return generator, nil
}
