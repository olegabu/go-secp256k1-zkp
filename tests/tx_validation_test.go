/** Grin transaction validation tests
 *  Created: 2019-07-31 <ao@ze1.org>
 *  https://labdlt.ru/mw/go-secp256k1-zkp
 */

package secp256k1_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
	secp256k1 "labdlt.ru/mw/go-secp256k1-zkp"
)

var txPrinted bool

type TxKernel struct {
	Features   string `json:"features"`
	Fee        string `json:"fee"`
	LockHeight string `json:"lock_height"`
	Excess     string `json:"excess"`
	ExcessSig  string `json:"excess_sig"`
}

type Tx struct {
	Offset string `json:"offset"`
	Body   struct {
		Inputs []struct {
			Features string `json:"features"`
			Commit   string `json:"commit"`
		} `json:"inputs"`
		Outputs []struct {
			Features string `json:"features"`
			Commit   string `json:"commit"`
			Proof    string `json:"proof"`
		} `json:"outputs"`
		Kernels []TxKernel `json:"kernels"`
	} `json:"body"`
}

func ReadTx(t *testing.T, filename string) *Tx {
	text, err := ioutil.ReadFile(filename) // 10_grin_repost.json
	assert.NoError(t, err)
	if !txPrinted {
		fmt.Println("=====BEGIN OF TRANSACTION=====")
		fmt.Println(string(text))
		fmt.Println("=====END OF TRANSACTION=====")
		txPrinted = true
	}
	tx := new(Tx)
	json.Unmarshal(text, tx)
	return tx
}

func TestTxVerify(t *testing.T) {

	tx := ReadTx(t, "10_grin_repost.json")

	var context, _ = secp256k1.ContextCreate(secp256k1.ContextBoth)

	var inputs []*secp256k1.Commitment
	for _, inputData := range tx.Body.Inputs {

		commitBytes, err := hex.DecodeString(inputData.Commit)
		assert.NoError(t, err)
		assert.NotEmpty(t, commitBytes)

		status, commitment, err := secp256k1.CommitmentParse(context, commitBytes)
		assert.True(t, status)
		assert.NoError(t, err)
		assert.NotNil(t, commitment)
		assert.IsType(t, secp256k1.Commitment{}, *commitment)

		inputs = append(inputs, commitment)
	}

	var outputs []*secp256k1.Commitment
	for _, outputData := range tx.Body.Outputs {

		commitBytes, err := hex.DecodeString(outputData.Commit)
		assert.NoError(t, err)
		assert.NotEmpty(t, commitBytes)

		status, commitment, err := secp256k1.CommitmentParse(context, commitBytes)
		assert.True(t, status)
		assert.NoError(t, err)
		assert.NotNil(t, commitment)
		assert.IsType(t, secp256k1.Commitment{}, *commitment)

		outputs = append(outputs, commitment)
	}

	statusSum, commitSum, err := secp256k1.CommitSum(context, inputs, outputs)
	assert.True(t, statusSum)
	assert.NoError(t, err)
	assert.NotNil(t, commitSum)
	assert.IsType(t, secp256k1.Commitment{}, *commitSum)
	fmt.Printf("commitSum=%v\n", *commitSum)

	statusVerify, err := secp256k1.VerifyTally(context, inputs, outputs)
	fmt.Printf("verifyTally=%v\n", statusVerify)
	assert.NoError(t, err)
	//assert.True(t, statusVerify == 1)

	statusSerialize, commitSerialize, err := secp256k1.CommitmentSerialize(context, outputs[0])
	assert.True(t, statusSerialize)
	assert.NoError(t, err)
	assert.NotEmpty(t, commitSerialize)
	fmt.Printf("commitSerialize=%v\n", commitSerialize)

	// Verify kernel sums

	var blind [32]byte
	fmt.Printf("blind=%v\n", blind)

	overage, err := strconv.ParseUint(tx.Body.Kernels[0].Fee, 10, 64)
	assert.NoError(t, err)

	// sum_commitments

	status, comOverage, err := secp256k1.Commit(context, blind, overage, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	assert.True(t, status)
	assert.NoError(t, err)
	assert.NotNil(t, comOverage)
	assert.IsType(t, secp256k1.Commitment{}, *comOverage)

	fmt.Printf("comOverage=0x%s\n", comOverage.Hex())

	if overage < 0 {
		inputs = append(inputs, comOverage)
	} else if overage > 0 {
		outputs = append(outputs, comOverage)

	}

	statusSumOverage, commitSumOverage, err := secp256k1.CommitSum(context, inputs, outputs)
	assert.True(t, statusSumOverage)
	assert.NoError(t, err)
	assert.NotNil(t, statusSumOverage)
	assert.IsType(t, secp256k1.Commitment{}, *commitSumOverage)

	fmt.Printf("commitSumOverage=0x%s\n", commitSumOverage.Hex())

	// sum_kernel_excesses
	offset_bytes, err := hex.DecodeString(tx.Offset)
	excess_bytes, err := hex.DecodeString(tx.Body.Kernels[0].Excess)

	var offset_32 [32]byte

	copy(offset_32[:], offset_bytes[:32])

	status, commit_offset, err := secp256k1.Commit(context, offset_32, 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	assert.True(t, status)
	assert.NoError(t, err)
	assert.NotNil(t, commit_offset)
	assert.IsType(t, secp256k1.Commitment{}, *commit_offset)

	fmt.Printf("commit_offset=0x%s\n", commit_offset.Hex())

	status_b, commit_excess, err := secp256k1.CommitmentParse(context, excess_bytes)
	assert.True(t, status_b)

	commits_offset_excess := [2]*secp256k1.Commitment{commit_offset, commit_excess}

	empty_array := make([]*secp256k1.Commitment, 0)

	statusSum, commitSumOffsetExcess, err := secp256k1.CommitSum(context, empty_array, commits_offset_excess[:])

	status, serializeSumOffsetExcess, err := secp256k1.CommitmentSerialize(context, commitSumOffsetExcess)

	fmt.Printf("commitSumOffsetExcess=0x%s\n", commitSumOffsetExcess.Hex())
	status, serializeCommitSumOverage, err := secp256k1.CommitmentSerialize(context, commitSumOverage)

	//fmt.Printf("serializeCommitSumOverage=0x%s\n", hex.EncodeToString(serializeCommitSumOverage[:]))
	assert.True(t, bytes.Compare(serializeSumOffsetExcess[:], serializeCommitSumOverage[:]) == 0)

	secp256k1.ContextDestroy(context)
}

// Schnorr/aggsig signature verify
func TestTxSigVerify(t *testing.T) {

	tx := ReadTx(t, "10_grin_kernel.json")

	var context, _ = secp256k1.ContextCreate(secp256k1.ContextBoth)

	//offset_bytes, err := hex.DecodeString(repostData.Offset)

	// Convert 'excess' value to a public key
	excessbytes, err := hex.DecodeString(tx.Body.Kernels[0].Excess)
	assert.NoError(t, err)

	status, excesscommit, err := secp256k1.CommitmentParse(context, excessbytes[:])
	assert.True(t, status)

	status, pubkey, err := secp256k1.CommitmentToPublicKey(context, excesscommit)
	assert.True(t, status)
	assert.NoError(t, err)
	assert.NotNil(t, pubkey)
	assert.IsType(t, secp256k1.PublicKey{}, *pubkey)
	fmt.Printf("excesspubkey=%s\n", hex.EncodeToString(excessbytes))

	// Parse ExcessSig value
	excsighex := tx.Body.Kernels[0].ExcessSig
	excsigbytes, err := hex.DecodeString(excsighex)
	assert.NoError(t, err)
	assert.Equal(t, excsighex, hex.EncodeToString(excsigbytes))
	fmt.Printf("excsigbytes=%s\n", excsighex)

	schsig, err := secp256k1.SchnorrsigParse(context, excsigbytes)
	assert.NoError(t, err)
	assert.NotNil(t, schsig)

	/*
		var sig64 [64]byte
		copy(sig64[:], excsig)
	*/ /*
		fea := make([]byte, 8)
		fee := make([]byte, 8)
		binary.BigEndian.PutUint64(fea, uint64(0))
		binary.BigEndian.PutUint64(fee, uint64(1000000))
		blk2b, _ := blake2b.New256(nil)
		blk2b.Write(fea)
		blk2b.Write(fee)
		msg := blk2b.Sum(nil)
		var msg32 [32]byte
		copy(msg32[:], msg)

		msghex := hex.EncodeToString(msg)
		fmt.Printf("msg=%s\n", msghex)*/

	feastr := strings.ToLower(tx.Body.Kernels[0].Features)
	var feaint int
	switch {
	case "plain" == feastr:
		feaint = 0
	case "coinbase" == feastr:
		feaint = 1
	case "lockheight" == feastr:
		feaint = 2
	default:
		t.FailNow()
	}
	assert.True(t, feaint >= 0 && feaint <= 2)
	feeint, err := strconv.ParseUint(tx.Body.Kernels[0].Fee, 10, 64)
	assert.NoError(t, err)
	assert.True(t, feeint >= 0)

	fea64, fee64 := make([]byte, 8), make([]byte, 8)
	binary.BigEndian.PutUint64(fea64, 0)
	binary.BigEndian.PutUint64(fee64, 7000000)
	hash, _ := blake2b.New256(nil)
	var fff [1]byte
	//hash.Write(append(fee64, fea64...))
	hash.Write(fff[:])
	hash.Write(fee64)
	msg := hash.Sum(nil)
	fmt.Printf("msg=%s\n", hex.EncodeToString(msg))

	status, err = secp256k1.AggsigVerifySingle(
		context,
		excsigbytes,
		msg,
		nil,
		pubkey,
		pubkey,
		nil,
		false,
	)
	spOK(t, status, err)
	fmt.Printf("AggsigVerifySingle=%v\n", status)

	err = secp256k1.SchnorrsigVerify(
		context,
		schsig,
		msg,
		pubkey,
	)
	assert.NoError(t, err)
	fmt.Printf("SchnorrsigVerify=%v\n", err)

	secp256k1.ContextDestroy(context)
}

// Verify RangeProof
func TestTxRangeproofVerify(t *testing.T) {

	tx := ReadTx(t, "10_grin_repost.json")

	var context, _ = secp256k1.ContextCreate(secp256k1.ContextBoth)

	commitBytes, err := hex.DecodeString(tx.Body.Outputs[0].Commit)
	status, BPCommitment, err := secp256k1.CommitmentParse(context, commitBytes)
	assert.True(t, status)
	assert.NoError(t, err)
	assert.NotNil(t, BPCommitment)
	assert.IsType(t, secp256k1.Commitment{}, *BPCommitment)
	fmt.Printf("BPCommitment=%v\n", *BPCommitment)

	scratch, err := secp256k1.ScratchSpaceCreate(context, 1024*1024)
	assert.NoError(t, err)

	bulletGenerators := secp256k1.BulletproofGeneratorsCreate(context, &secp256k1.GeneratorG, 256)

	BPToBytes, err := hex.DecodeString(tx.Body.Outputs[0].Proof)
	assert.NoError(t, err)
	fmt.Printf("BPToBytes=%v\n", BPToBytes)

	statusBPVerify, err := secp256k1.BulletproofRangeproofVerify(
		context,
		scratch,
		bulletGenerators,
		BPToBytes,
		nil, // min_values: NULL for all-zeroes minimum values to prove ranges above
		BPCommitment,
		64,
		&secp256k1.GeneratorH,
		nil)

	assert.True(t, statusBPVerify == 1)
	assert.NoError(t, err)

	secp256k1.ContextDestroy(context)
}

func reverseBytes(src []byte) []byte {
	cnt := len(src)
	dst := make([]byte, cnt)
	for i, x := 0, cnt-1; i < x; i, x = i+1, x-1 {
		dst[i], dst[x] = src[x], src[i]
	}
	return dst
}
