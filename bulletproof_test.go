package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBulletproofSingle(t *testing.T) {
	context, err := ContextCreate(ContextVerify | ContextSign)
	assert.NoError(t, err)

	// scratch, err := ScratchSpaceCreate(context, 1024*4096)
	// if err != nil {
	//     return
	// }
	// defer ScratchSpaceDestroy(scratch)

	// generators, err := BulletproofGeneratorsCreate(context, &GeneratorG, 2*64*2)
	// if err != nil {
	//     return
	// }
	// defer BulletproofGeneratorsDestroy(context, generators)

	value := uint64(12345678)

	blind := Random256()
	assert.NoError(t, err)

	commit, err := Commit(context, blind[:], value, &GeneratorH)
	assert.NoError(t, err)

	proof, err := BulletproofRangeproofProveSingle(context, nil, nil, value, blind[:], blind[:], nil, nil, nil)
	assert.NoError(t, err)

	// bulletproof, _, _, _, err := BulletproofRangeproofProve(context, scratch, generators, taux, &tone, &ttwo, []uint64{value}, nil, [][32]byte{blinding}, []*Commitment{commit}, &GeneratorH, 64,	blinding, blinding, nil, msg)
	prooferr := BulletproofRangeproofVerifySingle(context, nil, nil, append([]byte{1, 2, 3, 4}, proof[4:]...), commit, nil)
	assert.Error(t, prooferr)

	prooferr = BulletproofRangeproofVerifySingle(context, nil, nil, proof, commit, nil)
	assert.NoError(t, prooferr)
}

func TestBulletproofMulti(t *testing.T) {
	participantsCount := 3
	value := uint64(12345678)
	commonNonce := Random256()
	context, err := ContextCreate(ContextVerify | ContextSign)
	assert.NoError(t, err)

	blinds := make([][]byte, 0)

	var commit *Commitment
	for i := 0; i < participantsCount; i++ {
		blind := Random256()
		blinds = append(blinds, blind[:])

		if i == 0 {
			commit, err = Commit(context, blind[:], value, &GeneratorH)
			assert.NoError(t, err)
		} else {
			currentCommit, err := Commit(context, blind[:], 0, &GeneratorH)
			commit, err = CommitSum(context, []*Commitment{commit, currentCommit}, nil)
			assert.NoError(t, err)
		}
	}

	// first step
	publicTau1s := make([]*PublicKey, 0)
	publicTau2s := make([]*PublicKey, 0)
	for i := 0; i < participantsCount; i++ {
		_, _, publicTau1, publicTau2, err := BulletproofRangeproofProveMulti(context, nil, nil, nil, nil, nil,
			[]uint64{value}, [][]byte{blinds[i]}, []*Commitment{commit}, &GeneratorH, 64, commonNonce[:], blinds[i][:], nil, nil)
		assert.NoError(t, err)
		publicTau1s = append(publicTau1s, publicTau1)
		publicTau2s = append(publicTau2s, publicTau2)
	}

	_, sumPublicTau1, err := EcPubkeyCombine(context, publicTau1s)
	assert.NoError(t, err)
	_, sumPublicTau2, err := EcPubkeyCombine(context, publicTau2s)
	assert.NoError(t, err)

	// second step
	tauxs := make([][]byte, 0)
	for i := 0; i < participantsCount; i++ {
		_, taux, _, _, err := BulletproofRangeproofProveMulti(context, nil, nil, nil, sumPublicTau1, sumPublicTau2,
			[]uint64{value}, [][]byte{blinds[i]}, []*Commitment{commit}, &GeneratorH, 64, commonNonce[:], blinds[i][:], nil, nil)
		assert.NoError(t, err)
		tauxs = append(tauxs, taux)
	}

	sumTauxs, err := BlindSum(context, tauxs, nil)
	assert.NoError(t, err)

	// third step
	proof, _, _, _, err := BulletproofRangeproofProveMulti(context, nil, nil, sumTauxs[:], sumPublicTau1, sumPublicTau2,
		[]uint64{value}, [][]byte{blinds[0]}, []*Commitment{commit}, &GeneratorH, 64, commonNonce[:], blinds[0][:], nil, nil)
	assert.NoError(t, err)

	prooferr := BulletproofRangeproofVerifySingle(context, nil, nil, append([]byte{1, 2, 3, 4}, proof[4:]...), commit, nil)
	assert.Error(t, prooferr)

	prooferr = BulletproofRangeproofVerifySingle(context, nil, nil, proof, commit, nil)
	assert.NoError(t, prooferr)
}

func TestBulletproofMain(t *testing.T) {
	/*
		none, _ := ContextCreate(ContextNone)
		//sign, _ := ContextCreate(ContextSign)
		//vrfy, _ := ContextCreate(ContextVerify)
		both, _ := ContextCreate(ContextVerify | ContextSign)
		context := both

		scratch, _ := ScratchSpaceCreate(context, 1024*1024)
		defer ScratchSpaceDestroy(scratch)

		gens, err := BulletproofGeneratorsCreate(none, nil, 256)
		assert.Error(t, err)
		gens, err = BulletproofGeneratorsCreate(none, &GeneratorG, 256)
		defer BulletproofGeneratorsDestroy(none, gens)
		assert.NoError(t, err)

		//var proof []byte
		//proofptr := &proof[0]
		//plen := BulletproofMaxSize

		blind := []byte("   i am not a blinding factor   ")
		//blindlen := len(blind)
		blind_ptr := [4][]byte{blind[:], blind[:], blind[:], blind[:]}

		value := [4]uint64{1234, 4567, 8910, 1112}
		minvalue := [4]uint64{1000, 4567, 0, 5000}
		//minvalueptr := &minvalue

		//var rewindblind [32]byte
		//var rewindv int32

		var commits [4]*Commitment
		//commitarr := [1]*Commitment{commit[0]}

		//var ecount int32

		value_gen, err := GeneratorGenerate(both, blind)
		assert.True(t, err == nil && value_gen != nil)
		for i, v := range value {
			commit, err := Commit(both, blind, v, value_gen, &GeneratorG)
			assert.NoError(t, err)
			commits[i] = commit
		}*/
	/*
		// rangeproof_prove //
		_, err = BulletproofRangeproofProveSingle(sign, scratch, gens, value[:1], blind_ptr[:1], nil, value_gen, 64, blind, nil, nil, nil)
		assert.Error(t, err)
		_, err = BulletproofRangeproofProveSingle(both, scratch, gens, value[:1], blind_ptr[:1], nil, value_gen, 64, blind, nil, nil, nil)
		assert.NoError(t, err)
		_, err = BulletproofRangeproofProveSingle(both, scratch, gens, value[:1], blind_ptr[:1], nil, value_gen, 64, blind, nil, nil, nil)
		assert.NoError(t, err)

		_, err = BulletproofRangeproofProveSingle(sign, scratch, gens, value[:1], blind_ptr[:1], nil, value_gen, 64, blind, nil, nil, nil)
		assert.Error(t, err)
		_, err = BulletproofRangeproofProveSingle(vrfy, scratch, gens, value[:1], blind_ptr[:1], nil, value_gen, 64, blind, nil, nil, nil)
		assert.Error(t, err)
		_, err = BulletproofRangeproofProveSingle(both, scratch, gens, value[:1], blind_ptr[:1], nil, value_gen, 64, blind, nil, nil, nil)
		assert.NoError(t, err)
		_, err = BulletproofRangeproofProveSingle(both, scratch, gens, value[:2], blind_ptr[:2], nil, value_gen, 64, blind, nil, nil, nil)
		assert.NoError(t, err)
		_, err = BulletproofRangeproofProveSingle(both, scratch, gens, value[:4], blind_ptr[:4], nil, value_gen, 64, blind, nil, nil, nil) // too few gens //
		assert.Error(t, err)
	*/
	// ...

	// p, err := BulletproofRangeproofProveSingle(both, nil, nil, value[0], blind_ptr[0], blind, nil, nil, nil)
	// assert.NoError(t, err)
	//
	// // rangeproof verify //
	// err = BulletproofRangeproofVerify(both, nil, nil, p, []uint64{minvalue[0]}, []*Commitment{commits[0]}, 64, &GeneratorH, nil)
	// assert.NoError(t, err)

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
