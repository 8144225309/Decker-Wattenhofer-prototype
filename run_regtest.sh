#!/bin/bash
export PATH="/home/obscurity/bitcoin-30.2/bin:$PATH"
export LD_LIBRARY_PATH="/mnt/c/pirq2/Decker-Wattenhofer/superscalar/build"
cd /mnt/c/pirq2/Decker-Wattenhofer/superscalar/build
cmake .. 2>&1 | tail -3
make -j4 2>&1 | grep -E "error|warning|Built|Linking"
echo "--- Running all tests ---"
./test_superscalar --all 2>&1
