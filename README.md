# go-secp256k1-zkp [![Go Reference](https://pkg.go.dev/badge/github.com/olegabu/go-secp256k1-zkp.svg)](https://pkg.go.dev/github.com/olegabu/go-secp256k1-zkp)

This package provides bindings (using cgo) to [secp256k1-zkp](https://github.com/ElementsProject/secp256k1-zkp) 
C library which is an experimental fork of libsecp256k1 with support of Zero Knowledge Proof extrensions.

## Building

```bash
go build
```

## Testing GO code

```bash
go test
```

## Testing C library `secp256k1-zkp`

Tests can be run by calling `make test`
Coverage can be built by calling `make coverage`
To display a HTML code coverage report, call `make coverage-html`

## Notes

- secp256k1-zkp folder is a copy from its repo not a git submodule to avoid errors in using with module based packages

