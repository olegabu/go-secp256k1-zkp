package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBulletproofSingle(t *testing.T) {
	context, err := ContextCreate(ContextVerify | ContextSign)
	assert.NoError(t, err)

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
