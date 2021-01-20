/*
 This package implements Zero Knowledge Proof algorithms for Golang
 Contains Go bindings for the secp256k1-zkp C-library, which is
 based on the secp256k1 - a highly optimized implementation of the
 256-bit elliptic curve used in Bitcoin blockchain.
*/
package secp256k1

/*
#cgo CFLAGS: -I${SRCDIR}/secp256k1-zkp -I${SRCDIR}/secp256k1-zkp/src
#include "include/secp256k1_generator.h"
#include "include/secp256k1_rangeproof.h"
const secp256k1_generator secp256k1_generator_const_g = {{
	0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
	0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
	0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
	0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
}};
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
	// const secp256k1_generator secp256k1_generator_const_h = {{
	//     0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
	//     0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
	//     0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e, 0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
	//     0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68, 0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04}};
	GeneratorH = Generator{C.secp256k1_generator_h}
)

type GeneratorHex string
type GeneratorSerialized [33]byte
type GeneratorSerializedSlice []byte

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
	if context == nil {
		context = SharedContext(ContextNone)
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
	if context == nil {
		context = SharedContext(ContextNone)
	}
	C.secp256k1_generator_serialize(
		context.ctx,
		cBuf(bytes[:]),
		generator.gen)

	return
}

// Convert commitment object to array of bytes
func (gen *Generator) Bytes() (bytes [33]byte) {
	bytes = GeneratorSerialize(SharedContext(ContextNone), gen)
	return
}

func (gen *Generator) String() string {
	bytes := gen.Bytes()

	return hex.EncodeToString(bytes[:])
}

func GeneratorFromString(str string) (gen *Generator, err error) {
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return

	}
	gen, err = GeneratorParse(SharedContext(ContextNone), bytes)

	return
}

func GeneratorFromBytes(bytes []byte) (gen *Generator, err error) {
	gen, err = GeneratorParse(SharedContext(ContextNone), bytes)

	return
}

// String method serializes generator as a hex string
// Generator returns object created from serialized data bytes
// Returns nil if failed to parse
func (genser GeneratorSerialized) Generator() (generator *Generator) {
	gen, err := GeneratorParse(nil, genser[:])
	if err != nil {
		generator = gen
	}

	return
}

func (genser GeneratorSerialized) String() string {

	return string(genser[:])
}

func (genserslc GeneratorSerializedSlice) Generator() (generator *Generator) {
	var err error
	if generator, err = GeneratorParse(nil, genserslc); err == nil {
		return nil
	}
	return
}

func (genhex GeneratorHex) Generator() (generator *Generator) {
	str := string(genhex)
	if genser, err := hex.DecodeString(str); err == nil {

		return nil
	} else {
		if generator, err = GeneratorParse(nil, []byte(genser)); err == nil {

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
	if ctx == nil {
		ctx = SharedContext(ContextSign)
	}
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
	if ctx == nil {
		ctx = SharedContext(ContextSign)
	}
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
