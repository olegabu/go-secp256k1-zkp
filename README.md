# go-secp256k1-zkp

This package provides bindings (using cgo) to [secp256k1-zkp](https://github.com/mimblewimble/secp256k1-zkp) 
C library which is an experimental fork of libsecp256k1 with support for Pedersen commitments and range proofs.

## Contributing

To start developing, clone the package from github, and from the
source directory, run the following to install the package.

    git submodule update --init
    make

Tests can be run by calling `make test`
Coverage can be build by calling `make coverage`
To display a HTML code coverage report, call `make coverage-html`

Please make sure to include tests for new features.

