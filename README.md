# go-secp256k1-zkp

This package provides bindings (using cgo) to [secp256k1-zkp](https://github.com/mimblewimble/secp256k1-zkp) 
C library which is an experimental fork of libsecp256k1 with support for Pedersen commitments and range proofs.

## TODO

- folder secp256k1-zkp is a copy from its repo not a git submodule to avoid errors in using with module based packages
- go modules are not yet supported, use `unset GO111MODULE` before building
- some packages using this library fail to build with a link error, use `CFLAGS="-fPIC" make`
- investigate if C library can be linked statically, otherwise other projects need to build explicitely into `secp256k1-zkp/.libs`

## Building

```bash
make # builds the C library into secp256k1-zkp/.libs folder

unset GO111MODULE # in case it's set to the modern default in the profile
go install
```

## Testing GO code

```bash
cd tests
go test
```

## Testing C library `secp256k1-zkp`

Tests can be run by calling `make test`
Coverage can be built by calling `make coverage`
To display a HTML code coverage report, call `make coverage-html`
