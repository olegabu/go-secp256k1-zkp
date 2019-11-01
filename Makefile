
# gather options for tests
TESTARGS=$(TESTOPTIONS)

deps: deps-secp256k1-zkp

deps-secp256k1-zkp:
		cd secp256k1-zkp && ./autogen.sh && ./configure --enable-experimental --enable-module-ecdh --enable-module-recovery --enable-module-bulletproof --enable-module-rangeproof --enable-module-commitment --enable-module-generator --enable-module-aggsig --enable-ecmult-static-precomputation --enable-tests --disable-benchmark && make -j4 && cd ..
deps-secp256k1:
		cd secp256k1-zkp && ./autogen.sh && ./configure --enable-experimental --enable-module-ecdh --enable-module-recovery && make -j4 && cd ..
deps-1:
		cd secp256k1-zkp && make -j4 && cd ..

test: test-cleanup test-secp256k1
test-race: test-race-secp256k1

test-cleanup: test-cleanup-coverage test-cleanup-profile

test-cleanup-coverage:
	rm -rf coverage/ 2>> /dev/null; \
	mkdir coverage/

test-cleanup-profile:
	rm -rf profile/ 2>> /dev/null; \
	mkdir profile/

test-secp256k1: test-cleanup
	go test -coverprofile=coverage/secp256k1.out -v \
	labdlt.ru/mw/go-secp256k1-zkp... \
	$(TESTARGS)

test-race-secp256k1:
	go test -race -v \
	labdlt.ru/mw/zkp/secp256k1... \
	$(TESTARGS)

sanity: build-test test

# concat all coverage reports together
coverage-concat:
	echo "mode: set" > coverage/full && \
    grep -h -v "^mode:" coverage/*.out >> coverage/full

# full coverage report
coverage: coverage-concat
	go tool cover -func=coverage/full $(COVERAGEARGS)

# full coverage report
coverage-html: coverage-concat
	go tool cover -html=coverage/full $(COVERAGEARGS)
