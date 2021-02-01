/** Golang bindings for ElementsProject's secp256k1-zkp library
 *  Alexander Olkhovoy <ao@ze1.org>
 *  https://github.com/olegabu/go-secp256k1-zkp
 */
package secp256k1_test

/**********************************************************************
 * Copyright (c) 2018 Jonas Nick                                      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

/*
 * This file demonstrates how to use the MuSig module to create a multisignature.
 * Additionally, see the documentation in include/secp256k1_musig.h.
 */

import (
	"fmt"
	secp256k1 "github.com/olegabu/go-secp256k1-zkp"
)

/* Number of public keys involved in creating the aggregate signature */
const nSigners = 3

/* Create a key pair and store it in seckey and pubkey */
func createKeypair(ctx *secp256k1.Context) (seckey [32]byte, pubkey *secp256k1.XonlyPubkey, err error) {
	for {
		seckey = secp256k1.Random256()
		_, err = secp256k1.EcSeckeyVerify(ctx, seckey[:])
		if err == nil {
			/* The probability that this not a valid secret key is approximately 2^-128 */
			break
		}
	}
	keypair, err := secp256k1.KeypairCreate(ctx, seckey[:])
	if err != nil {
		return
	}
	pubkey, _, err = secp256k1.KeypairXonlyPubkey(ctx, keypair)

	return
}

/* Sign a message hash with the given key pairs and store the result in sig */
func sign(ctx *secp256k1.Context, seckeys [][32]byte, pubkeys []*secp256k1.XonlyPubkey, msg32 []byte) (sig [64]byte, err error) {
	var (
		musigSession [nSigners]*secp256k1.MusigSession
		nonceCommitment [nSigners][32]byte
		nonceCommitmentPtr [nSigners][]byte
		signerData [nSigners][]*secp256k1.MusigSessionSignerData
		nonce [nSigners][32]byte
		partialSig [nSigners]*secp256k1.MusigPartialSignature
		i, j int
	)

	for i = 0; i < nSigners; i++ {
		var (
			sessionId32 [32]byte
			combinedPk *secp256k1.XonlyPubkey
			preSession *secp256k1.MusigPreSession
		)

		/* Create combined pubkey and initialize signer data */
		combinedPk, preSession, err = secp256k1.MusigPubkeyCombine(ctx, nil, pubkeys)
		if err != nil {
			return
		}

		/* Create random session ID. It is absolutely necessary that the session ID
		 * is unique for every call of secp256k1_musig_session_init. Otherwise
		 * it's trivial for an attacker to extract the secret key! */
		sessionId32 = secp256k1.Random256()

		/* Initialize session */
		musigSession[i], signerData[i], nonceCommitment[i], err = secp256k1.MusigSessionInit(ctx, sessionId32[:], msg32, combinedPk, preSession, nSigners, i, seckeys[i][:])
		if err != nil {
			return
		}
		nonceCommitmentPtr[i] = nonceCommitment[i][:]
	}

	/* Communication round 1: Exchange nonce commitments */
	for i = 0; i < nSigners; i++ {
		/* Set nonce commitments in the signer data and get the own public nonce */
		nonce[i], err = secp256k1.MusigSessionGetPublicNonce(ctx, musigSession[i], signerData[i], nonceCommitmentPtr[:], nil)
		if err != nil {
			return
		}
	}

	/* Communication round 2: Exchange nonces */
	for i = 0; i < nSigners; i++ {
		for j = 0; j < nSigners; j++ {
			err = secp256k1.MusigSetNonce(ctx, signerData[i][j], nonce[j][:])
			if err != nil {
				/* Signer j's nonce does not match the nonce commitment. In this case
				 * abort the protocol. If you make another attempt at finishing the
				 * protocol, create a new session (with a fresh session ID!). */
				return
			}
		}
		_, err = secp256k1.MusigSessionCombineNonces(ctx, musigSession[i], signerData[i], nil)
		if err != nil {
			return
		}
	}
	for i = 0; i < nSigners; i++ {
		partialSig[i], err = secp256k1.MusigPartialSign(ctx, musigSession[i])
		if err != nil {
			return
		}
	}

	/* Communication round 3: Exchange partial signatures */
	for i = 0; i < nSigners; i++ {
		for j = 0; j < nSigners; j++ {
			/* To check whether signing was successful, it suffices to either verify
			 * the combined signature with the combined public key using
			 * secp256k1_schnorrsig_verify, or verify all partial signatures of all
			 * signers individually. Verifying the combined signature is cheaper but
			 * verifying the individual partial signatures has the advantage that it
			 * can be used to determine which of the partial signatures are invalid
			 * (if any), i.e., which of the partial signatures cause the combined
			 * signature to be invalid and thus the protocol run to fail. It's also
			 * fine to first verify the combined sig, and only verify the individual
			 * sigs if it does not work.
			 */
			err = secp256k1.MusigPartialSigVerify(ctx, musigSession[i], signerData[i][j], partialSig[j], pubkeys[j])
			if err != nil {
				return
			}
		}
	}

	sig, err = secp256k1.MusigPartialSigCombine(ctx, musigSession[0], partialSig[:])
	return
}

func ExampleMusig() {
	var (
		seckeys [nSigners][32]byte
		pubkeys [nSigners]*secp256k1.XonlyPubkey
		combinedPk *secp256k1.XonlyPubkey
		msg [32]byte
		sig [64]byte
		i int
	)

    /* Create a context for signing and verification */
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextBoth)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer secp256k1.ContextDestroy(ctx)

    /* Creating key pairs */
	for i = 0; i < nSigners; i++ {
		seckeys[i], pubkeys[i], err = createKeypair(ctx)
		if err != nil {
			fmt.Println(err)
			return
		}
    }

    /* Combining public keys */
    combinedPk, _, err = secp256k1.MusigPubkeyCombine(ctx, nil, pubkeys[:])
	if err != nil {
		fmt.Println(err)
		return
	}

    /* Signing message */
    msg = secp256k1.Random256()
    sig, err = sign(ctx, seckeys[:], pubkeys[:], msg[:])
	if err != nil {
		fmt.Println(err)
		return
	}

	/* Verifying signature */
	err = secp256k1.SchnorrsigVerify(ctx, secp256k1.SchnorrsigParse(sig[:]), msg[:], combinedPk)
	if err != nil {
		fmt.Println(err)
		return
	}

	/* Verifying broken signature */
	sig[3] ^= 1
	err = secp256k1.SchnorrsigVerify(ctx, secp256k1.SchnorrsigParse(sig[:]), msg[:], combinedPk)
	if err == nil {
		fmt.Println("FAIL: false positive for an invalid signature")
		return
	}

	/* Success */
	fmt.Println("OK")

    // Output: OK
}
