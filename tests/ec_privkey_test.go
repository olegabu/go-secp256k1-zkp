package secp256k1_test

import (
	"encoding/hex"
	"fmt"
	"github.com/olegabu/go-secp256k1-zkp"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

type PrivkeyTweakAddTestCase struct {
	PrivateKey string `yaml:"privkey"`
	Tweak      string `yaml:"tweak"`
	Tweaked    string `yaml:"tweaked"`
}

func (t *PrivkeyTweakAddTestCase) GetPrivateKey() []byte {
	public, err := hex.DecodeString(t.PrivateKey)
	if err != nil {
		panic("Invalid private key")
	}
	return public
}
func (t *PrivkeyTweakAddTestCase) GetTweak() []byte {
	tweak, err := hex.DecodeString(t.Tweak)
	if err != nil {
		panic(err)
	}
	return tweak
}
func (t *PrivkeyTweakAddTestCase) GetTweaked() []byte {
	tweaked, err := hex.DecodeString(t.Tweaked)
	if err != nil {
		panic(err)
	}
	return tweaked
}

type PrivkeyTweakAddFixtures []PrivkeyTweakAddTestCase

func GetPrivkeyTweakAddFixtures() PrivkeyTweakAddFixtures {
	source := readFile(PrivkeyTweakAddTestVectors)
	testCase := PrivkeyTweakAddFixtures{}
	err := yaml.Unmarshal(source, &testCase)
	if err != nil {
		panic(err)
	}
	return testCase
}

func TestPrivkeyTweakAddFixtures(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetPrivkeyTweakAddFixtures()

	for i := 0; i < 1; i++ {
		fixture := fixtures[i]
		priv := fixture.GetPrivateKey()
		tweak := fixture.GetTweak()

		r, err := secp256k1.EcPrivkeyTweakAdd(ctx, priv, tweak)
		spOK(t, r, err)

		assert.Equal(t, fixture.GetTweaked(), priv)
	}
}

type PrivkeyTweakMulTestCase struct {
	PrivateKey string `yaml:"privkey"`
	Tweak      string `yaml:"tweak"`
	Tweaked    string `yaml:"tweaked"`
}

func (t *PrivkeyTweakMulTestCase) GetPrivateKey() []byte {
	public, err := hex.DecodeString(t.PrivateKey)
	if err != nil {
		panic("Invalid private key")
	}
	return public
}
func (t *PrivkeyTweakMulTestCase) GetTweak() []byte {
	tweak, err := hex.DecodeString(t.Tweak)
	if err != nil {
		panic(err)
	}
	return tweak
}
func (t *PrivkeyTweakMulTestCase) GetTweaked() []byte {
	tweaked, err := hex.DecodeString(t.Tweaked)
	if err != nil {
		panic(err)
	}
	return tweaked
}

type PrivkeyTweakMulFixtures []PrivkeyTweakMulTestCase

func GetPrivkeyTweakMulFixtures() PrivkeyTweakMulFixtures {
	source := readFile(PrivkeyTweakMulTestVectors)
	testCase := PrivkeyTweakMulFixtures{}
	err := yaml.Unmarshal(source, &testCase)
	if err != nil {
		panic(err)
	}
	return testCase
}

func TestPrivkeyTweakMulFixtures(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetPrivkeyTweakMulFixtures()

	for i := 0; i < 1; i++ {
		description := fmt.Sprintf("Test case %d", i)
		t.Run(description, func(t *testing.T) {
			fixture := fixtures[i]
			priv := fixture.GetPrivateKey()
			tweak := fixture.GetTweak()

			r, err := secp256k1.EcPrivkeyTweakMul(ctx, priv, tweak)
			spOK(t, r, err)

			assert.Equal(t, fixture.GetTweaked(), priv)
		})
	}
}

func TestPrivkeyVerifyFixtures(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetPrivkeyTweakMulFixtures()
	for i := 0; i < 1; i++ {
		description := fmt.Sprintf("Test case %d", i)
		t.Run(description, func(t *testing.T) {
			fixture := fixtures[i]
			priv := fixture.GetPrivateKey()
			result, err := secp256k1.EcSeckeyVerify(ctx, priv)
			spOK(t, result, err)
		})
	}
}

func TestPrivkeyVerifyFailures(t *testing.T) {

	testCase := []struct {
		Priv  string
		Error string
	}{
		{
			Priv:  ``,
			Error: secp256k1.ErrorPrivateKeyNull,
		},
		{
			Priv:  `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`,
			Error: secp256k1.ErrorPrivateKeyInvalid,
		},
		{
			Priv:  `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142`,
			Error: secp256k1.ErrorPrivateKeyInvalid,
		},
	}

	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}
	for i, l := 0, len(testCase); i < l; i++ {
		description := fmt.Sprintf("Test case %d", i)
		t.Run(description, func(t *testing.T) {
			test := testCase[i]

			key, _ := hex.DecodeString(test.Priv)
			r, err := secp256k1.EcSeckeyVerify(ctx, key)
			assert.Equal(t, 0, r)
			assert.Error(t, err)
			assert.Equal(t, test.Error, err.Error())
		})
	}
}

func TestPrivkeyTweakAddChecksTweakSize(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	priv, _ := hex.DecodeString("e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9")
	badTweak, _ := hex.DecodeString("AAAA")

	r, err := secp256k1.EcPrivkeyTweakAdd(ctx, priv, badTweak)
	assert.Error(t, err)
	assert.Equal(t, 0, r)
	assert.Equal(t, secp256k1.ErrorTweakSize, err.Error())
}

func TestPrivkeyTweakMulChecksTweakSize(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	priv, _ := hex.DecodeString("e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9")
	badTweak, _ := hex.DecodeString("AAAA")

	r, err := secp256k1.EcPrivkeyTweakMul(ctx, priv, badTweak)
	assert.Error(t, err)
	assert.Equal(t, 0, r)
	assert.Equal(t, secp256k1.ErrorTweakSize, err.Error())
}

func TestPrivkeyTweakAddChecksPrivkeySize(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	tweak, _ := hex.DecodeString("e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9")
	priv, _ := hex.DecodeString("AAAA")

	r, err := secp256k1.EcPrivkeyTweakAdd(ctx, priv, tweak)
	assert.Error(t, err)
	assert.Equal(t, 0, r)
	assert.Equal(t, secp256k1.ErrorPrivateKeySize, err.Error())
}

func TestPrivkeyTweakAddChecksPrivkeyOverflow(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	priv, _ := hex.DecodeString("e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9")
	tweak, _ := hex.DecodeString("e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9")
	r, err := secp256k1.EcPrivkeyNegate(ctx, tweak)
	spOK(t, r, err)

	r, err = secp256k1.EcPrivkeyTweakAdd(ctx, priv, tweak)
	assert.Error(t, err)
	assert.Equal(t, 0, r)
	assert.Equal(t, secp256k1.ErrorTweakingPrivateKey, err.Error())
}

func TestPrivkeyTweakMulChecksPrivkeySize(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	priv, _ := hex.DecodeString("AAAA")
	tweak, _ := hex.DecodeString("e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9")

	r, err := secp256k1.EcPrivkeyTweakMul(ctx, priv, tweak)
	assert.Error(t, err)
	assert.Equal(t, 0, r)
	assert.Equal(t, secp256k1.ErrorPrivateKeySize, err.Error())
}

func TestPrivkeyNegate(t *testing.T) {
	pk1, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	pk2_will_sub_1, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000002")

	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	// pk_1 = -(1)
	pk_1, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	r, err := secp256k1.EcPrivkeyNegate(ctx, pk_1)
	spOK(t, r, err)

	// pk2_will_sub_1: = 2+(-(1)) %p
	r, err = secp256k1.EcPrivkeyTweakAdd(ctx, pk2_will_sub_1, pk_1)
	spOK(t, r, err)

	// therefore 1 = pk2_will_sub_1 %p
	assert.Equal(t, pk1, pk2_will_sub_1)
}

func TestPrivkeyNegateValidatesSize(t *testing.T) {
	ctx, err := secp256k1.ContextCreate(secp256k1.ContextSign | secp256k1.ContextVerify)
	if err != nil {
		panic(err)
	}

	// pk_1 = -(1)
	pk_1, _ := hex.DecodeString("")
	r, err := secp256k1.EcPrivkeyNegate(ctx, pk_1)
	assert.Equal(t, 0, r)
	assert.Equal(t, secp256k1.ErrorPrivateKeySize, err.Error())
	assert.Error(t, err)
}
