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
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"

	"github.com/olegabu/go-secp256k1-zkp"
)

var txPrinted bool

type Plain3 struct {
	Fee string `json:"fee"`
}

type Features3 struct {
	Plain Plain3 `json:"Plain"`
}

type Kernel3 struct {
	Features  Features3 `json:"features"`
	Excess    string    `json:"excess"`
	ExcessSig string    `json:"excess_sig"`
}

type Tx3 struct {
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
		Kernels []Kernel3 `json:"kernels"`
	} `json:"body"`
}

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

type Slate struct {
	Transaction Tx `json:"tx"`
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

func ReadTx3(t *testing.T, filename string) *Tx3 {
	text, err := ioutil.ReadFile(filename) // 10_grin_repost.json
	assert.NoError(t, err)
	if !txPrinted {
		fmt.Println("=====BEGIN OF TRANSACTION V3=====")
		fmt.Println(string(text))
		fmt.Println("=====END OF TRANSACTION V3=====")
		txPrinted = true
	}
	tx := new(Tx3)
	json.Unmarshal(text, tx)
	return tx
}

func ReadSlate(t *testing.T, filename string) *Slate {
	text, err := ioutil.ReadFile(filename) // 10_grin_repost.json
	assert.NoError(t, err)
	if !txPrinted {
		fmt.Println("=====BEGIN OF SLATE=====")
		fmt.Println(string(text))
		fmt.Println("=====END OF SLATE=====")
		txPrinted = true
	}
	slt := new(Slate)
	json.Unmarshal(text, slt)
	return slt
}

func TestTxVerify(t *testing.T) {

	tx := ReadSlate(t, "1g_final.json").Transaction

	var context, _ = secp256k1.ContextCreate(secp256k1.ContextBoth)

	var inputs []*secp256k1.Commitment
	for _, inputData := range tx.Body.Inputs {

		commitBytes, err := hex.DecodeString(inputData.Commit)
		assert.NoError(t, err)
		assert.NotEmpty(t, commitBytes)

		commitment, err := secp256k1.CommitmentParse(context, commitBytes)
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

		commitment, err := secp256k1.CommitmentParse(context, commitBytes)
		assert.NoError(t, err)
		assert.NotNil(t, commitment)
		assert.IsType(t, secp256k1.Commitment{}, *commitment)

		outputs = append(outputs, commitment)
	}

	commitSum, err := secp256k1.CommitSum(context, inputs, outputs)
	assert.NoError(t, err)
	assert.NotNil(t, commitSum)
	assert.IsType(t, secp256k1.Commitment{}, *commitSum)
	fmt.Printf("commitSum=%v\n", *commitSum)

	err = secp256k1.VerifyTally(context, inputs, outputs)
	//assert.NoError(t, err)
	//assert.True(t, statusVerify == 1)

	commitSerialize, err := secp256k1.CommitmentSerialize(context, outputs[0])
	assert.NoError(t, err)
	assert.NotEmpty(t, commitSerialize)
	fmt.Printf("commitSerialize=%v\n", commitSerialize)

	// Verify kernel sums

	var blind [32]byte
	fmt.Printf("blind=%v\n", blind)

	overage, err := strconv.ParseUint(tx.Body.Kernels[0].Fee, 10, 64)
	assert.NoError(t, err)

	// sum_commitments

	comOverage, err := secp256k1.Commit(context, blind[:], overage, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	assert.NoError(t, err)
	assert.NotNil(t, comOverage)
	assert.IsType(t, secp256k1.Commitment{}, *comOverage)

	fmt.Printf("comOverage=0x%s\n", comOverage.Hex(context))

	if overage < 0 {
		inputs = append(inputs, comOverage)
	} else if overage > 0 {
		outputs = append(outputs, comOverage)

	}

	commitSumOverage, err := secp256k1.CommitSum(context, inputs, outputs)
	assert.NoError(t, err)
	assert.NotNil(t, commitSumOverage)
	assert.IsType(t, secp256k1.Commitment{}, *commitSumOverage)

	fmt.Printf("commitSumOverage=0x%s\n", commitSumOverage.Hex(context))

	// sum_kernel_excesses
	offset_bytes, err := hex.DecodeString(tx.Offset)
	excess_bytes, err := hex.DecodeString(tx.Body.Kernels[0].Excess)

	var offset_32 [32]byte

	copy(offset_32[:], offset_bytes[:32])

	commit_offset, err := secp256k1.Commit(context, offset_32[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	assert.NoError(t, err)
	assert.NotNil(t, commit_offset)
	assert.IsType(t, secp256k1.Commitment{}, *commit_offset)

	fmt.Printf("commit_offset=0x%s\n", commit_offset.Hex(context))

	commit_excess, err := secp256k1.CommitmentParse(context, excess_bytes)

	commits_offset_excess := [2]*secp256k1.Commitment{commit_offset, commit_excess}

	empty_array := make([]*secp256k1.Commitment, 0)

	commitSumOffsetExcess, err := secp256k1.CommitSum(context, empty_array, commits_offset_excess[:])

	serializeSumOffsetExcess, err := secp256k1.CommitmentSerialize(context, commitSumOffsetExcess)

	fmt.Printf("commitSumOffsetExcess=0x%s\n", commitSumOffsetExcess.Hex(context))
	serializeCommitSumOverage, err := secp256k1.CommitmentSerialize(context, commitSumOverage)

	//fmt.Printf("serializeCommitSumOverage=0x%s\n", hex.EncodeToString(serializeCommitSumOverage[:]))
	assert.True(t, bytes.Compare(serializeSumOffsetExcess[:], serializeCommitSumOverage[:]) == 0)

	secp256k1.ContextDestroy(context)
}

// Schnorr/aggsig signature verify
func TestTxSigVerify(t *testing.T) {

	//tx := ReadSlate(t, "1g_final.json").Transaction
	tx := ReadTx(t, "100mg_repost.json")

	var context, _ = secp256k1.ContextCreate(secp256k1.ContextBoth)

	//offset_bytes, err := hex.DecodeString(repostData.Offset)

	// Convert 'excess' value to a public key
	excessbytes, err := hex.DecodeString(tx.Body.Kernels[0].Excess)
	assert.NoError(t, err)

	excesscommit, err := secp256k1.CommitmentParse(context, excessbytes[:])

	pubkey, err := secp256k1.CommitmentToPublicKey(context, excesscommit)
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

	var feeint uint64
	//feeint, err = strconv.ParseUint(tx.Body.Kernels[0].Fee, 10, 64)
	assert.NoError(t, err)
	assert.True(t, feeint >= 0)

	//if tx.Body.Kernels[0].Features.
	var feastr string
	//feastr = strings.ToLower(tx.Body.Kernels[0].Features)
	if feastr == "" {
		feastr = "plain"
		//feeint = uint64(tx.Body.Kernels[0].Features[0])
	}

	var feaint byte
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

	feei64 := make([]byte, 8)
	binary.BigEndian.PutUint64(feei64, feeint)

	hash, _ := blake2b.New256(nil)
	hash.Write([]byte{feaint})
	hash.Write(feei64[:])
	msg := hash.Sum(nil)

	fmt.Printf("msg=%s\n", hex.EncodeToString(msg))

	err = secp256k1.AggsigVerifySingle(
		context,
		excsigbytes,
		msg,
		nil,
		pubkey,
		nil,
		nil,
		false,
	)
	assert.NoError(t, err)
	fmt.Printf("AggsigVerifySingle=%v\n", err)

	// err = secp256k1.SchnorrsigVerify(
	// 	context,
	// 	schsig,
	// 	msg,
	// 	pubkey,
	// )
	// assert.NoError(t, err)
	// fmt.Printf("SchnorrsigVerify=%v\n", err)

	secp256k1.ContextDestroy(context)
}

// Verify RangeProof
func TestTxRangeproofVerify(t *testing.T) {

	tx := ReadSlate(t, "1g_final.json").Transaction

	var context, _ = secp256k1.ContextCreate(secp256k1.ContextBoth)
	defer secp256k1.ContextDestroy(context)

	commitBytes, err := hex.DecodeString(tx.Body.Outputs[0].Commit)
	BPCommitment, err := secp256k1.CommitmentParse(context, commitBytes)
	assert.NoError(t, err)
	assert.NotNil(t, BPCommitment)
	assert.IsType(t, secp256k1.Commitment{}, *BPCommitment)
	fmt.Printf("BPCommitment = %s\n", BPCommitment.Hex(context))

	scratch, err := secp256k1.ScratchSpaceCreate(context, 1024*1024)
	assert.NoError(t, err)

	bulletGenerators, err := secp256k1.BulletproofGeneratorsCreate(context, &secp256k1.GeneratorG, 256)

	BPToBytes, err := hex.DecodeString(tx.Body.Outputs[0].Proof)
	assert.NoError(t, err)
	fmt.Printf("BPToBytes = %s\n", BPToBytes)

	err = secp256k1.BulletproofRangeproofVerify(
		context,
		scratch,
		bulletGenerators,
		BPToBytes,
		nil, // min_values: NULL for all-zeroes minimum values to prove ranges above
		[]*secp256k1.Commitment{BPCommitment},
		64,
		&secp256k1.GeneratorH,
		nil)
	assert.NoError(t, err)

	err = secp256k1.BulletproofRangeproofVerifySingle(
		context,
		scratch,
		bulletGenerators,
		BPToBytes,
		BPCommitment,
		nil)
	assert.NoError(t, err)
}

func reverseBytes(src []byte) []byte {
	cnt := len(src)
	dst := make([]byte, cnt)
	for i, x := 0, cnt-1; i < x; i, x = i+1, x-1 {
		dst[i], dst[x] = src[x], src[i]
	}
	return dst
}

func TestTxVerify2(t *testing.T) {
	//var context, _ = secp256k1.ContextCreate(secp256k1.ContextBoth)
	//defer secp256k1.ContextDestroy(context)
	//tx := ReadSlate(t, "1g_final.json").Transaction

}
