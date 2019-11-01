# go-secp256k1-zkp

This package provides bindings (using cgo) to [secp256k1-zkp](https://github.com/mimblewimble/secp256k1-zkp) 
C library which is an experimental fork of libsecp256k1 with support for Pedersen commitments and range proofs.

## Building

Clone the package from github and run the following from the source directory.

```bash
git submodule update --init
make
```

## Testing

```bash
cd tests
go test
```

Tests can be run by calling `make test`
Coverage can be build by calling `make coverage`
To display a HTML code coverage report, call `make coverage-html`
