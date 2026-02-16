#!/bin/bash
export PATH="$HOME/bitcoin-28.0/bin:$PATH"

cd /mnt/c/pirq2/Decker-Wattenhofer/superscalar/build
make -j$(nproc) 2>&1 | tail -5

echo "=== Running unit tests ==="
export LD_LIBRARY_PATH=_deps/secp256k1-zkp-build/src:_deps/cjson-build
./test_superscalar --unit 2>&1
