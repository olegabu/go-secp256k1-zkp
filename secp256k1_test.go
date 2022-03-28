package secp256k1_test

import (
    "crypto/rand"
    "fmt"
    "io"
    "testing"

    "github.com/olegabu/go-secp256k1-zkp"
)

func testingRand32() [32]byte {
    key := [32]byte{}
    _, err := io.ReadFull(rand.Reader, key[:])
    if err != nil {
        panic(err)
    }
    return key
}
func testingRand(n int) []byte {
    key := make([]byte, n)
    _, err := io.ReadFull(rand.Reader, key[:])
    if err != nil {
        panic(err)
    }
    return key
}

func TestRand256(t *testing.T) {

    rnd := [2][32]byte{secp256k1.Random256(), secp256k1.Random256()}
    fmt.Printf("Random256(): %x\nRandom256(): %x\n", rnd[0], rnd[1])
    if rnd[0][0] == 0 || rnd[1][0] == 0 || rnd[0] == rnd[1] {
        t.Fail()
    }
}

func Test_ContextCreate1(t *testing.T) {

    params := uint(secp256k1.ContextSign | secp256k1.ContextVerify)
    ctx, err := secp256k1.ContextCreate(params)
    if err != nil {
        t.Fail()
    }

    clone, err := secp256k1.ContextClone(ctx)
    if err != nil {
        t.Fail()
    }

    secp256k1.ContextDestroy(clone)

    res := secp256k1.ContextRandomize(ctx, testingRand32())
    if res != 1 {
        t.Fail()
    }

    secp256k1.ContextDestroy(ctx)
}
