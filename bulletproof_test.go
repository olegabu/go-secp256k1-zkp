package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBulletproofMain(t *testing.T) {

	none, _ := ContextCreate(ContextNone)
	sign, _ := ContextCreate(ContextSign)
	//vrfy, _ := ContextCreate(ContextVerify)
	both, _ := ContextCreate(ContextVerify | ContextSign)
	context := both

	scratch, _ := ScratchSpaceCreate(context, 1024*1024)
	defer ScratchSpaceDestroy(scratch)

	gens, err := BulletproofGeneratorsCreate(none, nil, 256)
	assert.NoError(t, err)
	gens, err = BulletproofGeneratorsCreate(none, &GeneratorH, 256)
	defer BulletproofGeneratorsDestroy(none, gens)
	assert.NoError(t, err)

	//var proof [BulletproofMaxSize]byte
	//proofptr := &proof[0]
	//plen := BulletproofMaxSize

	blind := []byte("   i am not a blinding factor   ")
	//blindlen := len(blind)
	blind_ptr := [4][]byte{blind[:], blind[:], blind[:], blind[:]}

	value := [4]uint64{1234, 4567, 8910, 1112}
	//minvalue := [4]uint64{1000, 4567, 0, 5000}
	//minvalueptr := &minvalue

	//var rewindblind [32]byte
	//var rewindv int32

	var commit [4]*Commitment
	//commitarr := [1]*Commitment{commit[0]}

	//var ecount int32

	value_gen, err := GeneratorGenerate(both, blind)
	assert.True(t, err == nil && value_gen != nil)
	for i, v := range value {
		commit[i], err = Commit(both, blind, v, value_gen, &GeneratorH)
		assert.True(t, commit[i] != nil && err == nil)
	}

	// rangeproof_prove //
	_, err = BulletproofRangeproofProveSingle(sign, scratch, gens, value[:1], blind_ptr[:1], value_gen, blind, nil, nil)
	assert.Error(t, err)
	_, err = BulletproofRangeproofProveSingle(both, scratch, gens, value[:1], blind_ptr[:1], value_gen, blind, nil, nil)
	assert.NoError(t, err)
	_, err = BulletproofRangeproofProveSingle(both, scratch, gens, value[:1], blind_ptr[:1], value_gen, blind, nil, nil)
	assert.NoError(t, err)

	// assert.True(t, BulletproofRangeproofProve(sign, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0)
	// assert.True(t, BulletproofRangeproofProve(vrfy, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0)
	// assert.True(t, BulletproofRangeproofProve(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 1)
	// plen = BulletproofMaxSize
	// assert.True(t, BulletproofRangeproofProve(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 2, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 1)
	// plen = BulletproofMaxSize
	// assert.True(t, BulletproofRangeproofProve(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 4, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0) // too few gens //

	return
}

/*
none := ContextCreate(ContextNone)
sign := ContextCreate(ContextSign)
vrfy := ContextCreate(ContextVerify)
both := ContextCreate(ContextVerify | ContextSign)
context := &both

scratch := ScratchSpaceCreate(ctx, 1024 * 1024)
gens := BulletprorebootfGenerators(context)

valuegen := Generator(name)
pcommit := [4]Commitment
pcommitarr := pcommit_arr(&pcommit[0])
proof := [2000]C.uchar;
blind := [32]byte{"   i am not a blinding factor   "}
proofptr, blindptr := &proof[0], &blind[0]
prooflen, blindlen := sizeof(blind), sizeof(proof)
value := ([4]C.uint64_t){ 1234, 4567, 8910, 1112 } ;
min_value := [4] = { 1000, 4567, 0, 5000 } ;
const uint64_t *mv_ptr = min_value;
unsigned char rewind_blind[32];
size_t rewind_v;

int32_t ecount = 0;

blind_ptr[0] = blind;
blind_ptr[1] = blind;
blind_ptr[2] = blind;
blind_ptr[3] = blind;
pcommit_arr[0] = pcommit;

secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

CHECK(secp256k1_generator_generate(both, &value_gen, blind) != 0);
CHECK(secp256k1_pedersen_commit(both, &pcommit[0], blind, value[0], &value_gen, &secp256k1_generator_const_h) != 0);
CHECK(secp256k1_pedersen_commit(both, &pcommit[1], blind, value[1], &value_gen, &secp256k1_generator_const_h) != 0);
CHECK(secp256k1_pedersen_commit(both, &pcommit[2], blind, value[2], &value_gen, &secp256k1_generator_const_h) != 0);
CHECK(secp256k1_pedersen_commit(both, &pcommit[3], blind, value[3], &value_gen, &secp256k1_generator_const_h) != 0);

// generators //
gens = secp256k1_bulletproof_generators_create(none, NULL, 256);
CHECK(gens == NULL && ecount == 1);
gens = secp256k1_bulletproof_generators_create(none, &secp256k1_generator_const_h, 256);
CHECK(gens != NULL && ecount == 1);

// rangeproof_prove //
ecount = 0;
CHECK(secp256k1_bulletproof_rangeproof_prove(none, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0);
CHECK(ecount == 1);
CHECK(secp256k1_bulletproof_rangeproof_prove(sign, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0);
CHECK(ecount == 2);
CHECK(secp256k1_bulletproof_rangeproof_prove(vrfy, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0);
CHECK(ecount == 3);
CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 1, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 1);
CHECK(ecount == 3);
plen = 2000;
CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 2, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 1);
CHECK(ecount == 3);
plen = 2000;
CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, NULL, NULL, NULL, value, NULL, blind_ptr, NULL, 4, &value_gen, 64, blind, NULL, NULL, 0, NULL) == 0); // too few gens //
CHECK(ecount == 4);
*/

/*
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
	ok, err := AggsigVerifySingle(ctx, sig, message[:], nil, pubkey, nil, nil, noneg)
	assert.True(t, ok)
	assert.NoError(t, err)
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
*/
