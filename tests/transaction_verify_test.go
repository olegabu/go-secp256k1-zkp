package secp256k1_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	"github.com/olegabu/go-secp256k1-zkp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

type Transaction struct {
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
		Kernels []struct {
			Features   string `json:"features"`
			Fee        string `json:"fee"`
			LockHeight string `json:"lock_height"`
			Excess     string `json:"excess"`
			ExcessSig  string `json:"excess_sig"`
		} `json:"kernels"`
	} `json:"body"`
}

type TransactionCommits struct {
	StringCommits struct {
		Inputs  []string
		Outputs []string
	}
	TrueCommits struct {
		Inputs  []*secp256k1.Commitment
		Outputs []*secp256k1.Commitment
	}
}

var Commits TransactionCommits
var RepostData Transaction
var Context *secp256k1.Context
var Space *secp256k1.ScratchSpace

func setup() {
	RepostData = Transaction{}
	var Repost, _ = ioutil.ReadFile("1g_grin_repost_fix_kernel.json")
	json.Unmarshal(Repost, &RepostData)

	Commits = TransactionCommits{}

	Context, _ = secp256k1.ContextCreate(secp256k1.ContextBoth)

	Space, _ = secp256k1.ScratchSpaceCreate(ctx, 1024*1024)
}

func TestMain(m *testing.M) {
	setup()
	runTests := m.Run()
	os.Exit(runTests)

}

func TestCommitsVerify(t *testing.T) {

	for _, val := range RepostData.Body.Outputs {
		Commits.StringCommits.Outputs = append(Commits.StringCommits.Outputs, val.Commit)
		t.Run("Output_commit: "+val.Commit, func(t *testing.T) {
			TrueCommit := testCommitVerify(t, val.Commit)
			Commits.TrueCommits.Outputs = append(Commits.TrueCommits.Outputs, TrueCommit)
		})
	}

	for _, val := range RepostData.Body.Inputs {
		Commits.StringCommits.Inputs = append(Commits.StringCommits.Inputs, val.Commit)
		t.Run("Input_commit: "+val.Commit, func(t *testing.T) {
			TrueCommit := testCommitVerify(t, val.Commit)
			Commits.TrueCommits.Inputs = append(Commits.TrueCommits.Inputs, TrueCommit)
		})
	}
	t.Run("Check Inputs/Outputs not nil ", func(t *testing.T) {
		assert.NotNil(t, Commits.StringCommits.Outputs)
		assert.NotNil(t, Commits.TrueCommits.Outputs)
		assert.NotNil(t, Commits.StringCommits.Inputs)
		assert.NotNil(t, Commits.TrueCommits.Inputs)
	})

}

func testCommitVerify(t *testing.T, commit string) *secp256k1.Commitment {
	context, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	commitBytes, err := hex.DecodeString(commit)
	assert.NoError(t, err)
	assert.NotEmpty(t, commitBytes)
	commitment, err := secp256k1.CommitmentParse(context, commitBytes)
	assert.NoError(t, err)
	assert.NotNil(t, commitment)
	return commitment
}

func TestCommitsSumVerify(t *testing.T) {
	inputs := Commits.TrueCommits.Inputs
	outputs := Commits.TrueCommits.Outputs
	commitSum, err := secp256k1.CommitSum(Context, inputs, outputs)
	assert.NoError(t, err)
	assert.NotNil(t, commitSum)
	assert.IsType(t, secp256k1.Commitment{}, *commitSum)
	//fmt.Printf("commitSum=%v\n", *commitSum)
	//statusVerify, err := secp256k1.VerifyTally(Context, inputs, outputs)
	//fmt.Printf("verifyTally=%v\n", statusVerify)
	//assert.NoError(t, err)
	//assert.True(t, statusVerify == 1)

	commitSerialize, err := secp256k1.CommitmentSerialize(Context, outputs[0])
	assert.NoError(t, err)
	assert.NotEmpty(t, commitSerialize)
	//fmt.Printf("commitSerialize=%v\n", commitSerialize)

	// Verify kernel sums

	var blind [32]byte
	//fmt.Printf("blind=%v", blind)

	overage, err := strconv.ParseUint(RepostData.Body.Kernels[0].Fee, 10, 64)
	assert.NoError(t, err)

	// sum_commitments

	comOverage, err := secp256k1.Commit(Context, blind[:], overage, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	assert.NoError(t, err)
	assert.NotNil(t, comOverage)
	assert.IsType(t, secp256k1.Commitment{}, *comOverage)
	//fmt.Printf("comNone=%v\n", *comOverage)
	temp_inputs := inputs
	temp_outputs := outputs

	if overage < 0 {
		temp_inputs = append(temp_inputs, comOverage)
	} else if overage > 0 {
		temp_outputs = append(temp_outputs, comOverage)

	}

	commitSumOverage, err := secp256k1.CommitSum(Context, temp_inputs, temp_outputs)
	assert.NoError(t, err)
	assert.NotNil(t, commitSumOverage)
	assert.IsType(t, secp256k1.Commitment{}, *commitSumOverage)
	//fmt.Printf("commitSumOverage=%v\n", commitSumOverage)

	// sum_kernel_excesses
	offset_bytes, err := hex.DecodeString(RepostData.Offset)
	excess_bytes, err := hex.DecodeString(RepostData.Body.Kernels[0].Excess)

	var offset_32 [32]byte

	copy(offset_32[:], offset_bytes[:32])

	commit_offset, err := secp256k1.Commit(Context, offset_32[:], 0, &secp256k1.GeneratorH, &secp256k1.GeneratorG)
	assert.NoError(t, err)
	assert.NotNil(t, commit_offset)
	assert.IsType(t, secp256k1.Commitment{}, *commit_offset)
	//fmt.Printf("commit_offset=%v\n", *commit_offset)

	commit_excess, err := secp256k1.CommitmentParse(Context, excess_bytes)

	commits_offset_excess := [2]*secp256k1.Commitment{commit_offset, commit_excess}

	empty_array := make([]*secp256k1.Commitment, 0)

	commitSumOffsetExcess, err := secp256k1.CommitSum(Context, empty_array, commits_offset_excess[:])

	//fmt.Printf("sum_kernel_excesses=%v\n", commitSumOffsetExcess)

	serializeSumOffsetExcess, err := secp256k1.CommitmentSerialize(Context, commitSumOffsetExcess)
	serializecommitSumOverage, err := secp256k1.CommitmentSerialize(Context, commitSumOverage)
	//fmt.Println(serializeSumOffsetExcess)
	//fmt.Println(serializecommitSumOverage)
	assert.True(t, bytes.Compare(serializeSumOffsetExcess[:], serializecommitSumOverage[:]) == 0)
}

func TestTransactionRangeproofVerify(t *testing.T) {

	var context, _ = secp256k1.ContextCreate(secp256k1.ContextBoth)
	commitBytes, err := hex.DecodeString(RepostData.Body.Outputs[0].Commit)
	BPCommitment, err := secp256k1.CommitmentParse(context, commitBytes)
	assert.NoError(t, err)
	assert.NotNil(t, BPCommitment)
	assert.IsType(t, secp256k1.Commitment{}, *BPCommitment)
	//fmt.Printf("BPCommitment=%v\n", *BPCommitment)

	scratch, err := secp256k1.ScratchSpaceCreate(context, 1024*1024)
	assert.NoError(t, err)

	bulletGenerators, err := secp256k1.BulletproofGeneratorsCreate(context, &secp256k1.GeneratorG, 256)

	BPToBytes, err := hex.DecodeString(RepostData.Body.Outputs[0].Proof)
	assert.NoError(t, err)
	//fmt.Printf("BPToBytes=%v\n", BPToBytes)

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

}

func TestExcessSigVerify(t *testing.T) {

	// Convert 'excess' value to a public key
	excessbytes, err := hex.DecodeString(RepostData.Body.Kernels[0].Excess)
	assert.NoError(t, err)

	excessCommit, err := secp256k1.CommitmentParse(Context, excessbytes)
	assert.NoError(t, err)
	assert.IsType(t, secp256k1.Commitment{}, *excessCommit)

	pubkey, err := secp256k1.CommitmentToPublicKey(Context, excessCommit)
	assert.NoError(t, err)
	assert.NotNil(t, pubkey)
	assert.IsType(t, secp256k1.PublicKey{}, *pubkey)
	//fmt.Printf("excesspubkey=%v\n", *pubkey)

	// Parse ExcessSig value
	excesscSigBytes, err := hex.DecodeString(RepostData.Body.Kernels[0].ExcessSig)
	assert.NoError(t, err)

	excsigShnorr, err := secp256k1.SchnorrsigParse(Context, excesscSigBytes)
	assert.NoError(t, err)
	assert.NotNil(t, excsigShnorr)
	//fmt.Printf("excsig=%v\n", *excsigShnorr)

	excsigShnorrSer, err := secp256k1.SchnorrsigSerialize(Context, excsigShnorr)
	assert.NoError(t, err)
	assert.NotNil(t, excsigShnorrSer)
	//fmt.Printf("excsig=%v\n", excsigShnorrSer)

	//var msg32 = [32]byte{180, 65, 206, 143, 201, 132, 134, 10, 60, 31, 243, 125, 112, 68, 17, 203, 241, 186, 154, 193, 30, 50, 211, 32, 136, 158, 207, 206, 15, 9, 224, 187}

	var b hash.Hash

	b, _ = blake2b.New256(nil)

	type tuple struct {
		first  uint64
		second uint64
	}

	values := tuple{0, 1000000}

	buf1 := make([]byte, 8)
	buf2 := make([]byte, 8)

	binary.BigEndian.PutUint64(buf1, values.first)
	binary.BigEndian.PutUint64(buf2, values.second)

	b.Write(append(buf1, buf2...))

	msg := b.Sum(nil)
	//fmt.Println("msg", msg)

	//var excsigShnorrSerB []byte

	//excsigShnorrSerB = excsigShnorrSer[:]

	//excess_rust := []bytes{}

	//status_pb, pb_key, _ := secp256k1.EcPubkeyParse(context, []byte{89, 163, 18, 56, 146, 139, 121, 30, 26, 61, 191, 91, 180, 45, 188, 103, 69, 37, 206, 174, 57, 25, 243, 170, 98, 199, 180, 212, 126, 242, 135, 143, 105, 196, 245, 224, 175, 15, 239, 9, 194, 20, 181, 74, 214, 141, 45, 236, 142, 162, 47, 167, 43, 227, 108, 230, 69, 142, 163, 121, 109, 86, 47, 199})
	//assert.True(t, status_pb==1)
	//assert.NotNil(t, pb_key)
	//fmt.Println(pb_key)
	// verify_single(secp, sig, msg, None, &pubkey, Some(&pubkey), false

	err = secp256k1.AggsigVerifySingle(
		Context,
		excesscSigBytes,
		msg,
		nil,
		pubkey,
		pubkey,
		nil,
		false)
	assert.NoError(t, err)

	err = secp256k1.AggsigVerify(
		Context,
		Space,
		excesscSigBytes,
		msg,
		[]*secp256k1.PublicKey{pubkey})
	assert.NoError(t, err)

	err = secp256k1.SchnorrsigVerify(
		Context,
		excsigShnorr,
		msg,
		pubkey)
	assert.NoError(t, err)
}

func ReverseBytes(src []byte) []byte {
	cnt := len(src)
	dst := make([]byte, cnt)
	for i, x := 0, cnt-1; i < x; i, x = i+1, x-1 {
		dst[i], dst[x] = src[x], src[i]
	}
	return dst
}

//		sig	[]byte{252, 135, 79, 208, 4, 154, 17, 201, 190, 100, 156, 97, 95, 225, 162, 162, 196, 44, 114, 249, 126, 10, 158, 175, 76, 176, 134, 32, 202, 50, 103, 180, 243, 38, 90, 15, 218, 230, 103, 1, 166, 163, 238, 2, 184, 42, 182, 136, 46, 131, 43, 200, 4, 236, 227, 70, 203, 76, 175, 101, 145, 226, 226, 49},
//		pubkey	[]byte{180, 65, 206, 143, 201, 132, 134, 10, 60, 31, 243, 125, 112, 68, 17, 203, 241, 186, 154, 193, 30, 50, 211, 32, 136, 158, 207, 206, 15, 9, 224, 187},
/*

	fn verify_kernel_sums(
		&self,
		overage: i64,
		kernel_offset: BlindingFactor,
	) -> Result<((Commitment, Commitment)), Error> {
		// Sum all input|output|overage commitments.
		let utxo_sum = self.sum_commitments(overage)?;

		// Sum the kernel excesses accounting for the kernel offset.
		let (kernel_sum, kernel_sum_plus_offset) = self.sum_kernel_excesses(&kernel_offset)?;

		if utxo_sum != kernel_sum_plus_offset {
			return Err(Error::KernelSumMismatch);
		}

		Ok((utxo_sum, kernel_sum))
	}


	fn sum_commitments(&self, overage: i64) -> Result<Commitment, Error> {
		// gather the commitments
		let mut input_commits = self.inputs_committed();
		let mut output_commits = self.outputs_committed();

		// add the overage as output commitment if positive,
		// or as an input commitment if negative
		if overage != 0 {
			let over_commit = {
				let secp = static_secp_instance();
				let secp = secp.lock();
				let overage_abs = overage.checked_abs().ok_or_else(|| Error::InvalidValue)? as u64;
				secp.commit_value(overage_abs).unwrap()
			};
			if overage < 0 {
				input_commits.push(over_commit);
			} else {
				output_commits.push(over_commit);
			}
		}

		sum_commits(output_commits, input_commits)
	}

	fn sum_kernel_excesses(
		&self,
		offset: &BlindingFactor,
	) -> Result<(Commitment, Commitment), Error> {
		// then gather the kernel excess commitments
		let kernel_commits = self.kernels_committed();

		// sum the commitments
		let kernel_sum = sum_commits(kernel_commits, vec![])?;

		// sum the commitments along with the
		// commit to zero built from the offset
		let kernel_sum_plus_offset = {
			let secp = static_secp_instance();
			let secp = secp.lock();
			let mut commits = vec![kernel_sum];
			if *offset != BlindingFactor::zero() {
				let key = offset.secret_key(&secp)?;
				let offset_commit = secp.commit(0, key)?;
				commits.push(offset_commit);
			}
			secp.commit_sum(commits, vec![])?
		};

		Ok((kernel_sum, kernel_sum_plus_offset))
	}

			// Verification of final sig:
			let result = verify_single(
				&secp,
				&final_sig,
				&msg,
				None,
				&pk_sum,
				Some(&pk_sum),
				None,
				false,
			);
			assert!(result == true);

	// Check we can verify the sig using the kernel excess
	{
		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let msg = kernel_sig_msg();
		let sig_verifies =
			aggsig::verify_single_from_commit(&keychain.secp(), &final_sig, &msg, &kernel_excess);

		assert!(!sig_verifies.is_err());
	}


{180,65,206,143,201,132,134,10,60,31,243,125,112,68,17,203,241,186,154,193,30,50,211,32,136,158,207,206,15,9,224,187}


message

[0]:0
[1]:0
[2]:0
[3]:0
[4]:0
[5]:15
[6]:66
[7]:64

go msg [0 0 0 0 0 15 66 64]

[0 0 0 0 0 0 15 66 64]

pub fn verify_bullet_proof(
		&self,
		commit: Commitment,
		proof: RangeProof,
		extra_data_in: Option<Vec<u8>>,
	) -> Result<ProofRange, Error> {
		let n_bits = 64;

		let extra_data;
		let (extra_data_len, extra_data) = match extra_data_in {
			Some(d) => {
				extra_data = d;
				(extra_data.len(), extra_data.as_ptr())
			},
			None => (0, ptr::null()),
		};

		let commit = self.commit_parse(commit.0).unwrap();

		let success = unsafe {
			let scratch = ffi::secp256k1_scratch_space_create(self.ctx, SCRATCH_SPACE_SIZE);
			let result = ffi::secp256k1_bulletproof_rangeproof_verify(
				self.ctx,
				scratch,
				shared_generators(self.ctx),
				proof.proof.as_ptr(),
				proof.plen as size_t,
				ptr::null(), // min_values: NULL for all-zeroes minimum values to prove ranges above
				commit.0.as_ptr(),
				1,
				n_bits as size_t,
				constants::GENERATOR_H.as_ptr(),
				extra_data,
				extra_data_len as size_t,
			);
			//			ffi::secp256k1_bulletproof_generators_destroy(self.ctx, gens);
			ffi::secp256k1_scratch_space_destroy(scratch);
			result == 1
		};

		if success {
			Ok(ProofRange {
				min: 0,
				max: u64::MAX,
			})
		} else {
			Err(Error::InvalidRangeProof)
		}
	}

fn shared_generators(ctx: *mut ffi::Context) -> *mut ffi::BulletproofGenerators {
	unsafe {
		match SHARED_BULLETGENERATORS.clone() {
			Some(s) => s,
			None => {
				SHARED_BULLETGENERATORS = Some(ffi::secp256k1_bulletproof_generators_create(
					ctx,
					constants::GENERATOR_G.as_ptr(),
					MAX_GENERATORS,
				));
				SHARED_BULLETGENERATORS.unwrap()
			}
		}
	}
}



Display settings: variable format=auto, show disassembly=auto, numeric pointer values=off, container summaries=on.
Launching /home/vovok/src/grin-wallet/target/debug/libwallet-12b35e714cdb5023
Module loaded: /lib/x86_64-linux-gnu/ld-2.27.so. Symbols loaded.
Module loaded: [vdso].
Module loaded: /home/vovok/src/grin-wallet/target/debug/libwallet-12b35e714cdb5023. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/libdl.so.2. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/librt.so.1. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/libpthread.so.0. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/libgcc_s.so.1. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/libc.so.6. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/libm.so.6. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/libdl.so.2. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/librt.so.1. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/libpthread.so.0. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/libgcc_s.so.1. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/libc.so.6. Symbols loaded.
Module loaded: /lib/x86_64-linux-gnu/libm.so.6. Symbols loaded.

running 3 tests
test test_rewind_range_proof ... test test_rewind_range_proof has been running for over 60 seconds
test aggsig_sender_receiver_interaction_offset ... test aggsig_sender_receiver_interaction_offset has been running for over 60 seconds
test aggsig_sender_receiver_interaction ... test aggsig_sender_receiver_interaction has been running for over 60 seconds
?pubkey
{...}
0: {...}
0: {89, 163, 18, 56, 146, 139, 121, 30, 26, 61, 191, 91, 180, 45, ...}
[0]: 89
[1]: 163
[2]: 18
[3]: 56
[4]: 146
[5]: 139
[6]: 121
[7]: 30
[8]: 26
[9]: 61
[10]: 191
[11]: 91
[12]: 180
[13]: 45
[14]: 188
[15]: 103
[16]: 69
[17]: 37
[18]: 206
[19]: 174
[20]: 57
[21]: 25
[22]: 243
[23]: 170
[24]: 98
[25]: 199
[26]: 180
[27]: 212
[28]: 126
[29]: 242
[30]: 135
[31]: 143
[32]: 105
[33]: 196
[34]: 245
[35]: 224
[36]: 175
[37]: 15
[38]: 239
[39]: 9
[40]: 194
[41]: 20
[42]: 181
[43]: 74
[44]: 214
[45]: 141
[46]: 45
[47]: 236
[48]: 142
[49]: 162
[50]: 47
[51]: 167
[52]: 43
[53]: 227
[54]: 108
[55]: 230
[56]: 69
[57]: 142
[58]: 163
[59]: 121
[60]: 109
[61]: 86
[62]: 47
[63]: 199
var pubkey
(&secp256k1zkp::key::PublicKey) pubkey = 0x00007ffff6dfbdf0
?sig
{...}
0: {...}
0: {252, 135, 79, 208, 4, 154, 17, 201, 190, 100, 156, 97, 95, ...}
252,135,79,208,4,154,17,201,190,100,156,97,95,225,162,162,196,44,114,249,126,10,158,175,76,176,134,32,202,50,103,180,243,38,90,15,218,230,103,1,166,163,238,2,184,42,182,136,46,131,43,200,4,236,227,70,203,76,175,101,145,226,226,49

*/
