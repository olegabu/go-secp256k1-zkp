package secp256k1

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestXonlyPubkeyParseSerialize(t *testing.T) {

	sk := Random256()
	kp, err := KeypairCreate(SharedContext(ContextBoth), sk[:])
	assert.NoError(t, err)
	xopk, _, err := KeypairXonlyPubkey(SharedContext(ContextBoth), kp)
	assert.NoError(t, err)

	xopkser := XonlyPubkeySerialize(SharedContext(ContextBoth), xopk)
	xopkdec, err := XonlyPubkeyParse(SharedContext(ContextBoth), xopkser[:])
	assert.NoError(t, err)
	assert.Equal(t, xopk, xopkdec)

}
