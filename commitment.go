/* This package implements Zero Knowledge Proof algorithms for Golang
**
** Contains Go bindings for the secp256k1-zkp C-library, which is
** based on the secp256k1 - a highly optimized implementation of the
** 256-bit elliptic curve used in Bitcoin blockchain.
 */
package secp256k1

/*
import "C"
import (
	"encoding/hex"
	"errors"
	"unsafe"
)

/** Generate a commitment from two blinding factors.
 *  Returns 1: Commitment successfully created.
 *          0: Error. The blinding factor is larger than the group order
 *             (probability for random 32 byte number < 2^-127) or results in the
 *             point at infinity. Retry with a different factor.
 *  In:     ctx:        pointer to a context object (cannot be NULL)
 *          blind:      pointer to a 32-byte blinding factor (cannot be NULL)
 *          value:      pointer to a 32-byte blinding factor (cannot be NULL)
 *          value_gen:  value generator 'h'
 *          blind_gen:  blinding factor generator 'g'
 *  Out:    commit:     pointer to the commitment (cannot be NULL)
 *
 *  Blinding factors can be generated and verified in the same way as secp256k1 private keys for ECDSA.
*/
/* TODO
func BlindCommit(
	context *Context,
	blind []byte,
	value []byte,
	valuegen *Generator,
	blindgen *Generator,
) (
	commit *Commitment,
	err error,
) {
	commit = newCommitment()
	if 1 != C.secp256k1_pedersen_blind_commit(
		context.ctx,
		commit.com,
		cBuf(blind),
		cBuf(value),
		valuegen.gen,
		blindgen.gen) {

		return nil, errors.New("error creating commitments from two blinds")
	}
	return commit, nil
}
*/

/** Calculates the blinding factor x' = x + SHA256(xG+vH | xJ), used in the switch commitment x'G+vH
 *
 * Returns 1: Blinding factor successfully computed.
 *         0: Error. Retry with different values.
 *
 * Args:           ctx: pointer to a context object
 * Out:   blind_switch: blinding factor for the switch commitment
 * In:           blind: pointer to a 32-byte blinding factor
 *               value: unsigned 64-bit integer value to commit to
 *           value_gen: value generator 'h'
 *           blind_gen: blinding factor generator 'g'
 *       switch_pubkey: pointer to public key 'j'
 *
// TODO BlindSwitch
func BlindSwitch(
	context *Context,
	blind []byte,
	value uint64,
	valuegen *Generator,
	blindgen *Generator,
	switchpubkey *PublicKey,
) (
	result [32]byte,
	err error,
) {
	if 1 != C.secp256k1_blind_switch(
		context.ctx,
		cBuf(result[:]),
		cBuf(blind),
		C.uint64_t(value),
		valuegen.gen,
		blindgen.gen,
		switchpubkey.pk,
	) {
		err = errors.New(ErrorCommitmentSwitch)
	}
	return
}
*/
