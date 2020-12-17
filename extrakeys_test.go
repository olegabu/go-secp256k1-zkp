package secp256k1

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

const hexstr = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"

func TestXonlyPubkeyParseSerialize(t *testing.T) {
	in32, _ := hex.DecodeString(hexstr)
	xopk, err := XonlyPubkeyParse(SharedContext(ContextNone), in32)
	assert.NoError(t, err)

	out32 := XonlyPubkeySerialize(SharedContext(ContextNone), xopk)
	assert.Equal(t, hexstr, hex.EncodeToString(out32[:]))
}
