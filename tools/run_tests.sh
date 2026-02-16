#!/bin/bash
# Build and run all tests
export PATH="$HOME/bitcoin-28.0/bin:$PATH"

echo "=== Building ==="
cd /mnt/c/pirq2/Decker-Wattenhofer/superscalar/build
cmake .. -DCMAKE_BUILD_TYPE=Debug 2>&1 | tail -5
make -j$(nproc) 2>&1 | tail -20

echo ""
echo "=== Running ALL tests ==="
export LD_LIBRARY_PATH=_deps/secp256k1-zkp-build/src:_deps/cjson-build
./test_superscalar --all 2>&1
