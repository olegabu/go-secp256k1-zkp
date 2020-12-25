package secp256k1

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const count = 10

var ctx *Context

func init() {
	ctx, _ = ContextCreate(ContextBoth)
}

/* Musig tests
 *
void run_musig_tests(void) {
    int i;
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024 * 1024);

    for (i = 0; i < count; i++) {
        musig_simple_test(scratch);
    }
    musig_api_tests(scratch);
    musig_state_machine_tests(scratch);
    for (i = 0; i < count; i++) {
        // Run multiple times to ensure that pk and nonce have different y parities
        scriptless_atomic_swap(scratch);
        musig_tweak_test(scratch);
    }
    sha256_tag_test();

    secp256k1_scratch_space_destroy(ctx, scratch);
}
*/
func TestMusig(t *testing.T) {
	scratch, _ := ScratchSpaceCreate(ctx, 1024*1024)
	defer ScratchSpaceDestroy(ctx, scratch)

	for i := 0; i < count; i++ {
		testMusigSimple(t, scratch)
	}

	testMusigStateMachine(t, scratch)
}

/*
int secp256k1_xonly_pubkey_create(secp256k1_xonly_pubkey *pk, const unsigned char *seckey) {
    int ret;
    secp256k1_keypair keypair;
    ret = secp256k1_keypair_create(ctx, &keypair, seckey);
    ret &= secp256k1_keypair_xonly_pub(ctx, pk, NULL, &keypair);
    return ret;
}
*/
func xonlyPubkeyCreate(seckey []byte) (pubkey *XonlyPubkey, err error) {
	var keypair *Keypair
	keypair, err = KeypairCreate(ctx, seckey)
	if err == nil {
		pubkey, _, err = KeypairXonlyPubkey(ctx, keypair)
	}
	return
}

/* Just a simple (non-adaptor, non-tweaked) 2-of-2 MuSig combine, sign, verify
 * test.
 *
void musig_simple_test(secp256k1_scratch_space *scratch) {
    unsigned char sk[2][32];
    secp256k1_musig_session session[2];
    secp256k1_musig_session_signer_data signer0[2];
    secp256k1_musig_session_signer_data signer1[2];
    unsigned char nonce_commitment[2][32];
    unsigned char msg[32];
    secp256k1_xonly_pubkey combined_pk;
    secp256k1_musig_pre_session pre_session;
    unsigned char session_id[2][32];
    secp256k1_xonly_pubkey pk[2];
    const unsigned char *ncs[2];
    unsigned char public_nonce[3][32];
    secp256k1_musig_partial_signature partial_sig[2];
    unsigned char final_sig[64];

    secp256k1_testrand256(session_id[0]);
    secp256k1_testrand256(session_id[1]);
    secp256k1_testrand256(sk[0]);
    secp256k1_testrand256(sk[1]);
    secp256k1_testrand256(msg);

    CHECK(secp256k1_xonly_pubkey_create(&pk[0], sk[0]) == 1);
    CHECK(secp256k1_xonly_pubkey_create(&pk[1], sk[1]) == 1);

    CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &combined_pk, &pre_session, pk, 2) == 1);
    CHECK(secp256k1_musig_session_init(ctx, &session[1], signer1, nonce_commitment[1], session_id[1], msg, &combined_pk, &pre_session, 2, 1, sk[1]) == 1);
    CHECK(secp256k1_musig_session_init(ctx, &session[0], signer0, nonce_commitment[0], session_id[0], msg, &combined_pk, &pre_session, 2, 0, sk[0]) == 1);

    ncs[0] = nonce_commitment[0];
    ncs[1] = nonce_commitment[1];

    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &session[0], signer0, public_nonce[0], ncs, 2, NULL) == 1);
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &session[1], signer1, public_nonce[1], ncs, 2, NULL) == 1);

    CHECK(secp256k1_musig_set_nonce(ctx, &signer0[0], public_nonce[0]) == 1);
    CHECK(secp256k1_musig_set_nonce(ctx, &signer0[1], public_nonce[1]) == 1);
    CHECK(secp256k1_musig_set_nonce(ctx, &signer1[0], public_nonce[0]) == 1);
    CHECK(secp256k1_musig_set_nonce(ctx, &signer1[1], public_nonce[1]) == 1);

    CHECK(secp256k1_musig_session_combine_nonces(ctx, &session[0], signer0, 2, NULL, NULL) == 1);
    CHECK(secp256k1_musig_session_combine_nonces(ctx, &session[1], signer1, 2, NULL, NULL) == 1);

    CHECK(secp256k1_musig_partial_sign(ctx, &session[0], &partial_sig[0]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &session[0], &signer0[0], &partial_sig[0], &pk[0]) == 1);
    CHECK(secp256k1_musig_partial_sign(ctx, &session[1], &partial_sig[1]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &session[0], &signer0[1], &partial_sig[1], &pk[1]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &session[1], &signer1[1], &partial_sig[1], &pk[1]) == 1);

    CHECK(secp256k1_musig_partial_sig_combine(ctx, &session[0], final_sig, partial_sig, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig, msg, &combined_pk) == 1);
}
*/
func testMusigSimple(t *testing.T, scratch *ScratchSpace) {
	sessionid := [2][32]byte{Random256(), Random256()}
	sk := [2][32]byte{Random256(), Random256()}
	msg := Random256()

	var pk [2]*XonlyPubkey
	pk[0], _ = xonlyPubkeyCreate(sk[0][:])
	pk[1], _ = xonlyPubkeyCreate(sk[1][:])

	combinedpubkey, presession, err := MusigPubkeyCombine(ctx, scratch, pk[:])
	assert.NoError(t, err)

	var session [2]*MusigSession
	var noncecommitment [2][32]byte
	var signer1, signer0 []*MusigSessionSignerData
	session[1], signer1, noncecommitment[1], err = MusigSessionInit(ctx, sessionid[1][:], msg[:], combinedpubkey, presession, 2, 1, sk[1][:])
	assert.NoError(t, err)
	session[0], signer0, noncecommitment[0], err = MusigSessionInit(ctx, sessionid[0][:], msg[:], combinedpubkey, presession, 2, 0, sk[0][:])
	assert.NoError(t, err)

	ncs := [2][]byte{noncecommitment[0][:], noncecommitment[1][:]}

	var publicnonce [3][32]byte
	publicnonce[0], err = MusigSessionGetPublicNonce(ctx, session[0], signer0, ncs[:], nil)
	assert.NoError(t, err)
	publicnonce[1], err = MusigSessionGetPublicNonce(ctx, session[1], signer1, ncs[:], nil)
	assert.NoError(t, err)

	assert.NoError(t, MusigSetNonce(ctx, signer0[0], publicnonce[0][:]))
	assert.NoError(t, MusigSetNonce(ctx, signer0[1], publicnonce[1][:]))
	assert.NoError(t, MusigSetNonce(ctx, signer1[0], publicnonce[0][:]))
	assert.NoError(t, MusigSetNonce(ctx, signer1[1], publicnonce[1][:]))

	_, err = MusigSessionCombineNonces(ctx, session[0], signer0, nil)
	assert.NoError(t, err)
	_, err = MusigSessionCombineNonces(ctx, session[1], signer1, nil)
	assert.NoError(t, err)

	var partialsig [2]*MusigPartialSignature
	partialsig[0], err = MusigPartialSign(ctx, session[0])
	assert.NoError(t, err)
	assert.NoError(t, MusigPartialSigVerify(ctx, session[0], signer0[0], partialsig[0], pk[0]))

	partialsig[1], err = MusigPartialSign(ctx, session[1])
	assert.NoError(t, err)
	assert.NoError(t, MusigPartialSigVerify(ctx, session[0], signer0[1], partialsig[1], pk[1]))
	assert.NoError(t, MusigPartialSigVerify(ctx, session[1], signer1[1], partialsig[1], pk[1]))

	var finalsig [64]byte
	finalsig, err = MusigPartialSigCombine(ctx, session[0], partialsig[:])
	assert.NoError(t, err)

	schnorrsig := SchnorrsigParse(finalsig[:])
	assert.NoError(t, SchnorrsigVerify(ctx, schnorrsig, msg[:], combinedpubkey))
}

/* Initializes two sessions, one use the given parameters (session_id,
 * nonce_commitments, etc.) except that `session_tmp` uses new signers with different
 * public keys. The point of this test is to call `musig_session_get_public_nonce`
 * with signers from `session_tmp` who have different public keys than the correct
 * ones and return the resulting messagehash. This should not result in a different
 * messagehash because the public keys of the signers are only used during session
 * initialization.
 *
void musig_state_machine_diff_signer_msghash_test(unsigned char *msghash, secp256k1_xonly_pubkey *pks, secp256k1_xonly_pubkey *combined_pk, secp256k1_musig_pre_session *pre_session, const unsigned char * const *nonce_commitments, unsigned char *msg, unsigned char *nonce_other, unsigned char *sk, unsigned char *session_id) {
    secp256k1_musig_session session;
    secp256k1_musig_session session_tmp;
    unsigned char nonce_commitment[32];
    secp256k1_musig_session_signer_data signers[2];
    secp256k1_musig_session_signer_data signers_tmp[2];
    unsigned char sk_dummy[32];
    secp256k1_xonly_pubkey pks_tmp[2];
    secp256k1_xonly_pubkey combined_pk_tmp;
    secp256k1_musig_pre_session pre_session_tmp;
    unsigned char nonce[32];

    // Set up signers with different public keys
    secp256k1_testrand256(sk_dummy);
    pks_tmp[0] = pks[0];
    CHECK(secp256k1_xonly_pubkey_create(&pks_tmp[1], sk_dummy) == 1);
    CHECK(secp256k1_musig_pubkey_combine(ctx, NULL, &combined_pk_tmp, &pre_session_tmp, pks_tmp, 2) == 1);
    CHECK(secp256k1_musig_session_init(ctx, &session_tmp, signers_tmp, nonce_commitment, session_id, msg, &combined_pk_tmp, &pre_session_tmp, 2, 1, sk_dummy) == 1);

    CHECK(secp256k1_musig_session_init(ctx, &session, signers, nonce_commitment, session_id, msg, combined_pk, pre_session, 2, 0, sk) == 1);
    CHECK(memcmp(nonce_commitment, nonce_commitments[1], 32) == 0);
    // Call get_public_nonce with different signers than the signers the session was
    // initialized with.
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &session_tmp, signers, nonce, nonce_commitments, 2, NULL) == 1);
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &session, signers_tmp, nonce, nonce_commitments, 2, NULL) == 1);
    CHECK(secp256k1_musig_set_nonce(ctx, &signers[0], nonce_other) == 1);
    CHECK(secp256k1_musig_set_nonce(ctx, &signers[1], nonce) == 1);
    CHECK(secp256k1_musig_session_combine_nonces(ctx, &session, signers, 2, NULL, NULL) == 1);

    secp256k1_musig_compute_messagehash(ctx, msghash, &session);
}
*/
func testMusigStateMachineDiffSignerMsgHash(
	t *testing.T,
	pks []*XonlyPubkey,
	combinedpubkey *XonlyPubkey,
	presession *MusigPreSession,
	noncecommitments [][]byte,
	msg []byte,
	nonceother []byte,
	sk []byte,
	sessionid []byte,
) (
	msghash [32]byte,
) {
	var err error

	// Set up signers with different public keys
	skdummy := Random256()
	var pkstmp [2]*XonlyPubkey
	pkstmp[0] = pks[0]
	pkstmp[1], err = xonlyPubkeyCreate(skdummy[:])
	assert.NoError(t, err)
	combinedpubkeytmp, presessiontmp, err := MusigPubkeyCombine(ctx, nil, pkstmp[:])
	assert.NoError(t, err)
	sessiontmp, signerstmp, noncecommitment, err := MusigSessionInit(ctx, sessionid, msg, combinedpubkeytmp, presessiontmp, 2, 1, skdummy[:])
	assert.NoError(t, err)

	session, signers, noncecommitment, err := MusigSessionInit(ctx, sessionid, msg, combinedpubkey, presession, 2, 0, sk)
	assert.NoError(t, err)
	assert.Equal(t, noncecommitment[:], noncecommitments[1])

	// Call get_public_nonce with different signers than the signers the session was
	// initialized with.
	nonce, err := MusigSessionGetPublicNonce(ctx, sessiontmp, signers, noncecommitments, nil)
	assert.NoError(t, err)
	nonce, err = MusigSessionGetPublicNonce(ctx, session, signerstmp, noncecommitments, nil)
	assert.NoError(t, err)
	assert.NoError(t, MusigSetNonce(ctx, signers[0], nonceother))
	assert.NoError(t, MusigSetNonce(ctx, signers[1], nonce[:]))
	_, err = MusigSessionCombineNonces(ctx, session, signers, nil)

	msghash = musigComputeMessageHash(ctx, session)

	return
}

/* Create a new session (with a different session id) and tries to use that session
 * to combine nonces with given signers_other. This should fail, because the nonce
 * commitments of signers_other do not match the nonce commitments the new session
 * was initialized with. If do_test is 0, the correct signers are being used and
 * therefore the function should return 1.
 *
int musig_state_machine_diff_signers_combine_nonce_test(secp256k1_xonly_pubkey *combined_pk, secp256k1_musig_pre_session *pre_session, unsigned char *nonce_commitment_other, unsigned char *nonce_other, unsigned char *msg, unsigned char *sk, secp256k1_musig_session_signer_data *signers_other, int do_test) {
    secp256k1_musig_session session;
    secp256k1_musig_session_signer_data signers[2];
    secp256k1_musig_session_signer_data *signers_to_use;
    unsigned char nonce_commitment[32];
    unsigned char session_id[32];
    unsigned char nonce[32];
    const unsigned char *ncs[2];

    // Initialize new signers
    secp256k1_testrand256(session_id);
    CHECK(secp256k1_musig_session_init(ctx, &session, signers, nonce_commitment, session_id, msg, combined_pk, pre_session, 2, 1, sk) == 1);
    ncs[0] = nonce_commitment_other;
    ncs[1] = nonce_commitment;
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &session, signers, nonce, ncs, 2, NULL) == 1);
    CHECK(secp256k1_musig_set_nonce(ctx, &signers[0], nonce_other) == 1);
    CHECK(secp256k1_musig_set_nonce(ctx, &signers[1], nonce) == 1);
    CHECK(secp256k1_musig_set_nonce(ctx, &signers[1], nonce) == 1);
    secp256k1_musig_session_combine_nonces(ctx, &session, signers_other, 2, NULL, NULL);
    if (do_test) {
        signers_to_use = signers_other;
    } else {
        signers_to_use = signers;
    }
    return secp256k1_musig_session_combine_nonces(ctx, &session, signers_to_use, 2, NULL, NULL);
}
*/
func testStateMachineDiffSignersCombineNonce(
	t *testing.T,
	combinedpk *XonlyPubkey,
	presession *MusigPreSession,
	noncecommitmentother []byte,
	nonceother []byte,
	msg []byte,
	sk []byte,
	signersother []*MusigSessionSignerData,
	dotest int,
) error {
	// Initialize new signers
	sessionid := Random256()
	session, signers, noncecommitment, err := MusigSessionInit(ctx, sessionid[:], msg, combinedpk, presession, 2, 1, sk)
	assert.NoError(t, err)
	var ncs [2][]byte
	ncs[0] = noncecommitmentother
	ncs[1] = noncecommitment[:]
	nonce, err := MusigSessionGetPublicNonce(ctx, session, signers, ncs[:], nil)
	assert.NoError(t, err)
	assert.NoError(t, MusigSetNonce(ctx, signers[0], nonceother))
	assert.NoError(t, MusigSetNonce(ctx, signers[1], nonce[:]))
	assert.NoError(t, MusigSetNonce(ctx, signers[1], nonce[:]))
	_, err = MusigSessionCombineNonces(ctx, session, signersother, nil)
	//assert.NoError(t, err)
	var signerstouse []*MusigSessionSignerData
	if dotest != 0 {
		signerstouse = signersother
	} else {
		signerstouse = signers
	}
	_, err = MusigSessionCombineNonces(ctx, session, signerstouse, nil)

	return err
}

/* Initializes a session with the given session_id, signers, pk, msg etc.
 * parameters but without a message. Will test that the message must be
 * provided with `get_public_nonce`.
 *
void musig_state_machine_late_msg_test(secp256k1_xonly_pubkey *pks, secp256k1_xonly_pubkey *combined_pk, secp256k1_musig_pre_session *pre_session, unsigned char *nonce_commitment_other, unsigned char *nonce_other, unsigned char *sk, unsigned char *session_id, unsigned char *msg) {
    // Create context for testing ARG_CHECKs by setting an illegal_callback.
    secp256k1_context *ctx_tmp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int ecount = 0;
    secp256k1_musig_session session;
    secp256k1_musig_session_signer_data signers[2];
    unsigned char nonce_commitment[32];
    const unsigned char *ncs[2];
    unsigned char nonce[32];
    secp256k1_musig_partial_signature partial_sig;

    secp256k1_context_set_illegal_callback(ctx_tmp, counting_illegal_callback_fn, &ecount);
    CHECK(secp256k1_musig_session_init(ctx, &session, signers, nonce_commitment, session_id, NULL, combined_pk, pre_session, 2, 1, sk) == 1);
    ncs[0] = nonce_commitment_other;
    ncs[1] = nonce_commitment;

    // Trying to get the nonce without providing a message fails.
    CHECK(ecount == 0);
    CHECK(secp256k1_musig_session_get_public_nonce(ctx_tmp, &session, signers, nonce, ncs, 2, NULL) == 0);
    CHECK(ecount == 1);

    // Providing a message should make get_public_nonce succeed.
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &session, signers, nonce, ncs, 2, msg) == 1);
    // Trying to set the message again fails.
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_session_get_public_nonce(ctx_tmp, &session, signers, nonce, ncs, 2, msg) == 0);
    CHECK(ecount == 2);

    // Check that it's working
    CHECK(secp256k1_musig_set_nonce(ctx, &signers[0], nonce_other) == 1);
    CHECK(secp256k1_musig_set_nonce(ctx, &signers[1], nonce) == 1);
    CHECK(secp256k1_musig_session_combine_nonces(ctx, &session, signers, 2, NULL, NULL) == 1);
    CHECK(secp256k1_musig_partial_sign(ctx, &session, &partial_sig));
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &session, &signers[1], &partial_sig, &pks[1]));
    secp256k1_context_destroy(ctx_tmp);
}
*/
func testStateMachineLateMsg(
	t *testing.T,
	pks []*XonlyPubkey,
	combinedpk *XonlyPubkey,
	presession *MusigPreSession,
	noncecommitmentother []byte,
	nonceother []byte,
	sk []byte,
	sessionid []byte,
	msg []byte,
) {
	// Create context for testing ARG_CHECKs by setting an illegal_callback.
	ctxtmp, err := ContextCreate(ContextNone)
	defer ContextDestroy(ctxtmp)

	session, signers, noncecommitment, err := MusigSessionInit(ctx, sessionid, nil, combinedpk, presession, 2, 1, sk)
	assert.NoError(t, err)
	var ncs [2][]byte
	ncs[0] = noncecommitmentother
	ncs[1] = noncecommitment[:]

	// Trying to get the nonce without providing a message fails.
	var nonce [32]byte
	//assert.Panics(t, func(){ nonce, err = MusigSessionGetPublicNonce(ctxtmp, session, signers, ncs[:], nil) })

	// Providing a message should make get_public_nonce succeed.
	nonce, err = MusigSessionGetPublicNonce(ctx, session, signers, ncs[:], msg)
	assert.NoError(t, err)
	// Trying to set the message again fails.
	//assert.Panics(t, func(){ nonce, err = MusigSessionGetPublicNonce(ctxtmp, session, signers, ncs[:], msg) })

	// Check that it's working
	assert.NoError(t, MusigSetNonce(ctx, signers[0], nonceother))
	assert.NoError(t, MusigSetNonce(ctx, signers[1], nonce[:]))
	_, err = MusigSessionCombineNonces(ctx, session, signers, nil)
	assert.NoError(t, err)
	partialsig, err := MusigPartialSign(ctx, session)
	assert.NoError(t, err)
	assert.NoError(t, MusigPartialSigVerify(ctx, session, signers[1], partialsig, pks[1]))
}

/* State machine test
 *
void musig_state_machine_tests(secp256k1_scratch_space *scratch) {
    secp256k1_context *ctx_tmp = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_VERIFY);
    size_t i;
    secp256k1_musig_session session[2];
    secp256k1_musig_session_signer_data signers0[2];
    secp256k1_musig_session_signer_data signers1[2];
    unsigned char nonce_commitment[2][32];
    unsigned char session_id[2][32];
    unsigned char msg[32];
    unsigned char sk[2][32];
    secp256k1_xonly_pubkey pk[2];
    secp256k1_xonly_pubkey combined_pk;
    secp256k1_musig_pre_session pre_session;
    unsigned char nonce[2][32];
    const unsigned char *ncs[2];
    secp256k1_musig_partial_signature partial_sig[2];
    unsigned char sig[64];
    unsigned char msghash1[32];
    unsigned char msghash2[32];
    int ecount;

    secp256k1_context_set_illegal_callback(ctx_tmp, counting_illegal_callback_fn, &ecount);
    ecount = 0;

    // Run state machine with the same objects twice to test that it's allowed to
    // reinitialize session and session_signer_data.
    for (i = 0; i < 2; i++) {
        // Setup
        secp256k1_testrand256(session_id[0]);
        secp256k1_testrand256(session_id[1]);
        secp256k1_testrand256(sk[0]);
        secp256k1_testrand256(sk[1]);
        secp256k1_testrand256(msg);
        CHECK(secp256k1_xonly_pubkey_create(&pk[0], sk[0]) == 1);
        CHECK(secp256k1_xonly_pubkey_create(&pk[1], sk[1]) == 1);
        CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &combined_pk, &pre_session, pk, 2) == 1);
        CHECK(secp256k1_musig_session_init(ctx, &session[0], signers0, nonce_commitment[0], session_id[0], msg, &combined_pk, &pre_session, 2, 0, sk[0]) == 1);
        CHECK(secp256k1_musig_session_init(ctx, &session[1], signers1, nonce_commitment[1], session_id[1], msg, &combined_pk, &pre_session, 2, 1, sk[1]) == 1);
        // Can't combine nonces unless we're through round 1 already
        ecount = 0;
        CHECK(secp256k1_musig_session_combine_nonces(ctx_tmp, &session[0], signers0, 2, NULL, NULL) == 0);
        CHECK(ecount == 1);

        // Set nonce commitments
        ncs[0] = nonce_commitment[0];
        ncs[1] = nonce_commitment[1];
        CHECK(secp256k1_musig_session_get_public_nonce(ctx, &session[0], signers0, nonce[0], ncs, 2, NULL) == 1);
        // Calling the function again is not okay
        ecount = 0;
        CHECK(secp256k1_musig_session_get_public_nonce(ctx_tmp, &session[0], signers0, nonce[0], ncs, 2, NULL) == 0);
        CHECK(ecount == 1);

        // Get nonce for signer 1
        CHECK(secp256k1_musig_session_get_public_nonce(ctx, &session[1], signers1, nonce[1], ncs, 2, NULL) == 1);

        // Set nonces
        CHECK(secp256k1_musig_set_nonce(ctx, &signers0[0], nonce[0]) == 1);
        // Can't set nonce that doesn't match nonce commitment
        CHECK(secp256k1_musig_set_nonce(ctx, &signers0[1], nonce[0]) == 0);
        // Set correct nonce
        CHECK(secp256k1_musig_set_nonce(ctx, &signers0[1], nonce[1]) == 1);

        // Combine nonces
        CHECK(secp256k1_musig_session_combine_nonces(ctx, &session[0], signers0, 2, NULL, NULL) == 1);
        // Not everyone is present from signer 1's view
        CHECK(secp256k1_musig_session_combine_nonces(ctx, &session[1], signers1, 2, NULL, NULL) == 0);
        // Make everyone present
        CHECK(secp256k1_musig_set_nonce(ctx, &signers1[0], nonce[0]) == 1);
        CHECK(secp256k1_musig_set_nonce(ctx, &signers1[1], nonce[1]) == 1);

        // Can't combine nonces from signers of a different session
        CHECK(musig_state_machine_diff_signers_combine_nonce_test(&combined_pk, &pre_session, nonce_commitment[0], nonce[0], msg, sk[1], signers1, 1) == 0);
        CHECK(musig_state_machine_diff_signers_combine_nonce_test(&combined_pk, &pre_session, nonce_commitment[0], nonce[0], msg, sk[1], signers1, 0) == 1);

        // Partially sign
        CHECK(secp256k1_musig_partial_sign(ctx, &session[0], &partial_sig[0]) == 1);
        // Can't verify, sign or combine signatures until nonce is combined
        ecount = 0;
        CHECK(secp256k1_musig_partial_sig_verify(ctx_tmp, &session[1], &signers1[0], &partial_sig[0], &pk[0]) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_musig_partial_sign(ctx_tmp, &session[1], &partial_sig[1]) == 0);
        CHECK(ecount == 2);
        memset(&partial_sig[1], 0, sizeof(partial_sig[1]));
        CHECK(secp256k1_musig_partial_sig_combine(ctx_tmp, &session[1], sig, partial_sig, 2) == 0);
        CHECK(ecount == 3);

        CHECK(secp256k1_musig_session_combine_nonces(ctx, &session[1], signers1, 2, NULL, NULL) == 1);
        CHECK(secp256k1_musig_partial_sig_verify(ctx, &session[1], &signers1[0], &partial_sig[0], &pk[0]) == 1);
        // messagehash should be the same as a session whose get_public_nonce was called
        // with different signers (i.e. they diff in public keys). This is because the
        // public keys of the signers is set in stone when initializing the session.
        secp256k1_musig_compute_messagehash(ctx, msghash1, &session[1]);
        musig_state_machine_diff_signer_msghash_test(msghash2, pk, &combined_pk, &pre_session, ncs, msg, nonce[0], sk[1], session_id[1]);
        CHECK(memcmp(msghash1, msghash2, 32) == 0);
        CHECK(secp256k1_musig_partial_sign(ctx, &session[1], &partial_sig[1]) == 1);

        CHECK(secp256k1_musig_partial_sig_verify(ctx, &session[1], &signers1[1], &partial_sig[1], &pk[1]) == 1);
        // Wrong signature
        CHECK(secp256k1_musig_partial_sig_verify(ctx, &session[1], &signers1[1], &partial_sig[0], &pk[1]) == 0);
        // Can't get the public nonce until msg is set
        musig_state_machine_late_msg_test(pk, &combined_pk, &pre_session, nonce_commitment[0], nonce[0], sk[1], session_id[1], msg);
    }
    secp256k1_context_destroy(ctx_tmp);
}
*/
func testMusigStateMachine(t *testing.T, scratch *ScratchSpace) {
	var (
		err                                   error
		session                               [2]*MusigSession
		signers0, signers1                    []*MusigSessionSignerData
		noncecommitment, sessionid, sk, nonce [2][32]byte
		msg, msghash1, msghash2               [32]byte
		pk                                    [2]*XonlyPubkey
		combinedpk                            *XonlyPubkey
		presession                            *MusigPreSession
		ncs                                   [2][]byte
		partialsig                            [2]*MusigPartialSignature
	)

	ctxtmp, err := ContextCreate(ContextNone)
	defer ContextDestroy(ctxtmp)

	// Run state machine with the same objects twice to test that it's allowed to
	// reinitialize session and session_signer_data.
	for i := 0; i < 2; i++ {
		// Setup
		sessionid[0] = Random256()
		sessionid[1] = Random256()
		sk[0] = Random256()
		sk[1] = Random256()
		msg = Random256()
		pk[0], err = xonlyPubkeyCreate(sk[0][:])
		assert.NoError(t, err)
		pk[1], err = xonlyPubkeyCreate(sk[1][:])
		assert.NoError(t, err)
		combinedpk, presession, err = MusigPubkeyCombine(ctx, scratch, pk[:])
		assert.NoError(t, err)
		session[0], signers0, noncecommitment[0], err = MusigSessionInit(ctx, sessionid[0][:], msg[:], combinedpk, presession, 2, 0, sk[0][:])
		assert.NoError(t, err)
		session[1], signers1, noncecommitment[1], err = MusigSessionInit(ctx, sessionid[1][:], msg[:], combinedpk, presession, 2, 1, sk[1][:])
		assert.NoError(t, err)
		// Can't combine nonces unless we're through round 1 already
		//assert.Panics(t, func(){ _, err = MusigSessionCombineNonces(ctxtmp, session[0], signers0, nil) })

		// Set nonce commitments
		ncs[0] = noncecommitment[0][:]
		ncs[1] = noncecommitment[1][:]
		nonce[0], err = MusigSessionGetPublicNonce(ctx, session[0], signers0, ncs[:], nil)
		assert.NoError(t, err)
		// Calling the function again is not okay
		//assert.Panics(t, func(){ _, err = MusigSessionGetPublicNonce(ctxtmp, session[0], signers0, ncs[:], nil) })

		// Get nonce for signer 1
		nonce[1], err = MusigSessionGetPublicNonce(ctx, session[1], signers1, ncs[:], nil)

		// Set nonces
		assert.NoError(t, MusigSetNonce(ctx, signers0[0], nonce[0][:]))
		// Can't set nonce that doesn't match nonce commitment
		assert.Error(t, MusigSetNonce(ctx, signers0[1], nonce[0][:]))
		// Set correct nonce
		assert.NoError(t, MusigSetNonce(ctx, signers0[1], nonce[1][:]))

		// Combine nonces
		_, err = MusigSessionCombineNonces(ctx, session[0], signers0, nil)
		assert.NoError(t, err)
		// Not everyone is present from signer 1's view
		_, err = MusigSessionCombineNonces(ctx, session[1], signers1, nil)
		assert.Error(t, err)
		// Make everyone present
		assert.NoError(t, MusigSetNonce(ctx, signers1[0], nonce[0][:]))
		assert.NoError(t, MusigSetNonce(ctx, signers1[1], nonce[1][:]))

		// Can't combine nonces from signers of a different session
		//assert.Error(t, testStateMachineDiffSignersCombineNonce(t, combinedpk, presession, noncecommitment[0][:], nonce[0][:], msg[:], sk[1][:], signers1, 1))
		// Combine nonces
		assert.NoError(t, testStateMachineDiffSignersCombineNonce(t, combinedpk, presession, noncecommitment[0][:], nonce[0][:], msg[:], sk[1][:], signers1, 0))

		// Partially sign
		partialsig[0], err = MusigPartialSign(ctx, session[0])
		assert.NoError(t, err)
		// Can't verify, sign or combine signatures until nonce is combined
		//assert.Panics(t, func(){ assert.Error(t, MusigPartialSigVerify(ctxtmp, session[1], signers1[0], partialsig[0], pk[0])) })
		//assert.Panics(t, func(){
		//	partialsig[1], err = MusigPartialSign(ctxtmp, session[1])
		//	assert.Error(t, err)
		//})
		//var zeropartialsig MusigPartialSignature
		//*partialsig[1] = zeropartialsig
		//assert.Panics(t, func(){
		//	_, err = MusigPartialSigCombine(ctxtmp, session[1], partialsig[:])
		//	assert.Error(t, err)
		//})

		_, err = MusigSessionCombineNonces(ctx, session[1], signers1, nil)
		assert.NoError(t, err)
		assert.NoError(t, MusigPartialSigVerify(ctx, session[1], signers1[0], partialsig[0], pk[0]))
		// messagehash should be the same as a session whose get_public_nonce was called
		// with different signers (i.e. they diff in public keys). This is because the
		// public keys of the signers is set in stone when initializing the session.
		msghash1 = musigComputeMessageHash(ctx, session[1])
		msghash2 = testMusigStateMachineDiffSignerMsgHash(t, pk[:], combinedpk, presession, ncs[:], msg[:], nonce[0][:], sk[1][:], sessionid[1][:])
		assert.Equal(t, msghash1, msghash2)

		partialsig[1], err = MusigPartialSign(ctx, session[1])
		assert.NoError(t, err)

		assert.NoError(t, MusigPartialSigVerify(ctx, session[1], signers1[1], partialsig[1], pk[1]))
		// Wrong signature
		assert.Error(t, MusigPartialSigVerify(ctx, session[1], signers1[1], partialsig[0], pk[1]))
		// Can't get the public nonce until msg is set
		testStateMachineLateMsg(t, pk[:], combinedpk, presession, noncecommitment[0][:], nonce[0][:], sk[1][:], sessionid[1][:], msg[:])
	}
}

/* Throughout this test "a" and "b" refer to two hypothetical blockchains,
 * while the indices 0 and 1 refer to the two signers. Here signer 0 is
 * sending a-coins to signer 1, while signer 1 is sending b-coins to signer 0.
 * Signer 0 produces the adaptor signatures.
 *
void scriptless_atomic_swap(secp256k1_scratch_space *scratch) {
    unsigned char final_sig_a[64];
    unsigned char final_sig_b[64];
    secp256k1_musig_partial_signature partial_sig_a[2];
    secp256k1_musig_partial_signature partial_sig_b_adapted[2];
    secp256k1_musig_partial_signature partial_sig_b[2];
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor_extracted[32];
    secp256k1_pubkey pub_adaptor;

    unsigned char seckey_a[2][32];
    unsigned char seckey_b[2][32];
    secp256k1_xonly_pubkey pk_a[2];
    secp256k1_xonly_pubkey pk_b[2];
    secp256k1_musig_pre_session pre_session_a;
    secp256k1_musig_pre_session pre_session_b;
    secp256k1_xonly_pubkey combined_pk_a;
    secp256k1_xonly_pubkey combined_pk_b;
    secp256k1_musig_session musig_session_a[2];
    secp256k1_musig_session musig_session_b[2];
    unsigned char noncommit_a[2][32];
    unsigned char noncommit_b[2][32];
    const unsigned char *noncommit_a_ptr[2];
    const unsigned char *noncommit_b_ptr[2];
    unsigned char pubnon_a[2][32];
    unsigned char pubnon_b[2][32];
    int combined_nonce_parity_a;
    int combined_nonce_parity_b;
    secp256k1_musig_session_signer_data data_a[2];
    secp256k1_musig_session_signer_data data_b[2];

    const unsigned char seed[32] = "still tired of choosing seeds...";
    const unsigned char msg32_a[32] = "this is the message blockchain a";
    const unsigned char msg32_b[32] = "this is the message blockchain b";

    // Step 1: key setup
    secp256k1_testrand256(seckey_a[0]);
    secp256k1_testrand256(seckey_a[1]);
    secp256k1_testrand256(seckey_b[0]);
    secp256k1_testrand256(seckey_b[1]);
    secp256k1_testrand256(sec_adaptor);

    CHECK(secp256k1_xonly_pubkey_create(&pk_a[0], seckey_a[0]));
    CHECK(secp256k1_xonly_pubkey_create(&pk_a[1], seckey_a[1]));
    CHECK(secp256k1_xonly_pubkey_create(&pk_b[0], seckey_b[0]));
    CHECK(secp256k1_xonly_pubkey_create(&pk_b[1], seckey_b[1]));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pub_adaptor, sec_adaptor));

    CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &combined_pk_a, &pre_session_a, pk_a, 2));
    CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &combined_pk_b, &pre_session_b, pk_b, 2));

    CHECK(secp256k1_musig_session_init(ctx, &musig_session_a[0], data_a, noncommit_a[0], seed, msg32_a, &combined_pk_a, &pre_session_a, 2, 0, seckey_a[0]));
    CHECK(secp256k1_musig_session_init(ctx, &musig_session_a[1], data_a, noncommit_a[1], seed, msg32_a, &combined_pk_a, &pre_session_a, 2, 1, seckey_a[1]));
    noncommit_a_ptr[0] = noncommit_a[0];
    noncommit_a_ptr[1] = noncommit_a[1];

    CHECK(secp256k1_musig_session_init(ctx, &musig_session_b[0], data_b, noncommit_b[0], seed, msg32_b, &combined_pk_b, &pre_session_b, 2, 0, seckey_b[0]));
    CHECK(secp256k1_musig_session_init(ctx, &musig_session_b[1], data_b, noncommit_b[1], seed, msg32_b, &combined_pk_b, &pre_session_b, 2, 1, seckey_b[1]));
    noncommit_b_ptr[0] = noncommit_b[0];
    noncommit_b_ptr[1] = noncommit_b[1];

    // Step 2: Exchange nonces
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &musig_session_a[0], data_a, pubnon_a[0], noncommit_a_ptr, 2, NULL));
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &musig_session_a[1], data_a, pubnon_a[1], noncommit_a_ptr, 2, NULL));
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &musig_session_b[0], data_b, pubnon_b[0], noncommit_b_ptr, 2, NULL));
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &musig_session_b[1], data_b, pubnon_b[1], noncommit_b_ptr, 2, NULL));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_a[0], pubnon_a[0]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_a[1], pubnon_a[1]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_b[0], pubnon_b[0]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_b[1], pubnon_b[1]));
    CHECK(secp256k1_musig_session_combine_nonces(ctx, &musig_session_a[0], data_a, 2, &combined_nonce_parity_a, &pub_adaptor));
    CHECK(secp256k1_musig_session_combine_nonces(ctx, &musig_session_a[1], data_a, 2, NULL, &pub_adaptor));
    CHECK(secp256k1_musig_session_combine_nonces(ctx, &musig_session_b[0], data_b, 2, &combined_nonce_parity_b, &pub_adaptor));
    CHECK(secp256k1_musig_session_combine_nonces(ctx, &musig_session_b[1], data_b, 2, NULL, &pub_adaptor));

    // Step 3: Signer 0 produces partial signatures for both chains.
    CHECK(secp256k1_musig_partial_sign(ctx, &musig_session_a[0], &partial_sig_a[0]));
    CHECK(secp256k1_musig_partial_sign(ctx, &musig_session_b[0], &partial_sig_b[0]));

    // Step 4: Signer 1 receives partial signatures, verifies them and creates a
    // partial signature to send B-coins to signer 0.
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &musig_session_a[1], data_a, &partial_sig_a[0], &pk_a[0]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &musig_session_b[1], data_b, &partial_sig_b[0], &pk_b[0]) == 1);
    CHECK(secp256k1_musig_partial_sign(ctx, &musig_session_b[1], &partial_sig_b[1]));

    // Step 5: Signer 0 adapts its own partial signature and combines it with the
    // partial signature from signer 1. This results in a complete signature which
    // is broadcasted by signer 0 to take B-coins.
    CHECK(secp256k1_musig_partial_sig_adapt(ctx, &partial_sig_b_adapted[0], &partial_sig_b[0], sec_adaptor, combined_nonce_parity_b));
    memcpy(&partial_sig_b_adapted[1], &partial_sig_b[1], sizeof(partial_sig_b_adapted[1]));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, &musig_session_b[0], final_sig_b, partial_sig_b_adapted, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig_b, msg32_b, &combined_pk_b) == 1);

    // Step 6: Signer 1 extracts adaptor from the published signature, applies it to
    // other partial signature, and takes A-coins.
    CHECK(secp256k1_musig_extract_secret_adaptor(ctx, sec_adaptor_extracted, final_sig_b, partial_sig_b, 2, combined_nonce_parity_b) == 1);
    CHECK(memcmp(sec_adaptor_extracted, sec_adaptor, sizeof(sec_adaptor)) == 0); // in real life we couldn't check this, of course
    CHECK(secp256k1_musig_partial_sig_adapt(ctx, &partial_sig_a[0], &partial_sig_a[0], sec_adaptor_extracted, combined_nonce_parity_a));
    CHECK(secp256k1_musig_partial_sign(ctx, &musig_session_a[1], &partial_sig_a[1]));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, &musig_session_a[1], final_sig_a, partial_sig_a, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig_a, msg32_a, &combined_pk_a) == 1);
}
*/

/* Checks that hash initialized by secp256k1_musig_sha256_init_tagged has the
 * expected state.
 *
void sha256_tag_test(void) {
    char tag[17] = "MuSig coefficient";
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_tagged;
    unsigned char buf[32];
    unsigned char buf2[32];
    size_t i;

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, (unsigned char *) tag, 17);
    secp256k1_sha256_finalize(&sha, buf);
    // buf = SHA256("MuSig coefficient")

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_sha256_write(&sha, buf, 32);
    // Is buffer fully consumed?
    CHECK((sha.bytes & 0x3F) == 0);

    // Compare with tagged SHA
    secp256k1_musig_sha256_init_tagged(&sha_tagged);
    for (i = 0; i < 8; i++) {
        CHECK(sha_tagged.s[i] == sha.s[i]);
    }
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_sha256_write(&sha_tagged, buf, 32);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_sha256_finalize(&sha_tagged, buf2);
    CHECK(memcmp(buf, buf2, 32) == 0);
}
*/
